# Copyright (c) 2016 EMC Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import binascii
import random
import re
import string

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
from oslo_utils import excutils
from oslo_utils import units
import six

from cinder import context
from cinder import exception
from cinder.i18n import _
from cinder.i18n import _LE
from cinder.i18n import _LI
from cinder.objects import fields
from cinder.volume.drivers.coprhd.helpers import (
    authentication as coprhd_auth)
from cinder.volume.drivers.coprhd.helpers import (
    commoncoprhdapi as coprhd_utils)
from cinder.volume.drivers.coprhd.helpers import (
    consistencygroup as coprhd_cg)
from cinder.volume.drivers.coprhd.helpers import exportgroup as coprhd_eg
from cinder.volume.drivers.coprhd.helpers import host as coprhd_host
from cinder.volume.drivers.coprhd.helpers import snapshot as coprhd_snap
from cinder.volume.drivers.coprhd.helpers import tag as coprhd_tag
from cinder.volume.drivers.coprhd.helpers import network as coprhd_network

from cinder.volume.drivers.coprhd.helpers import (
    virtualarray as coprhd_varray)
from cinder.volume.drivers.coprhd.helpers import volume as coprhd_vol
from cinder.volume import volume_types

from powervc_cinder.db import api as powervc_db_api
from powervc_cinder.volume import discovery_driver


LOG = logging.getLogger(__name__)

MAX_RETRIES = 10
INTERVAL_10_SEC = 10

volume_opts = [
    cfg.StrOpt('coprhd_hostname',
               default=None,
               help='Hostname for the CoprHD Instance'),
    cfg.PortOpt('coprhd_port',
                default=4443,
                help='Port for the CoprHD Instance'),
    cfg.StrOpt('coprhd_username',
               default=None,
               help='Username for accessing the CoprHD Instance'),
    cfg.StrOpt('coprhd_password',
               default=None,
               help='Password for accessing the CoprHD Instance',
               secret=True),
    cfg.StrOpt('coprhd_tenant',
               default=None,
               help='Tenant to utilize within the CoprHD Instance'),
    cfg.StrOpt('coprhd_project',
               default=None,
               help='Project to utilize within the CoprHD Instance'),
    cfg.StrOpt('coprhd_varray',
               default=None,
               help='Virtual Array to utilize within the CoprHD Instance'),
    cfg.BoolOpt('coprhd_emulate_snapshot',
                default=False,
                help='True | False to indicate if the storage array '
                'in CoprHD is VMAX or VPLEX'),
    cfg.BoolOpt('verify_server_certificate',
                default=False,
                help='Verify server certificate, by default certificate '
                'verification is not performed'),
    cfg.StrOpt('server_certificate_path',
               default=None,
               help='Server certificate path')
]

CONF = cfg.CONF
CONF.register_opts(volume_opts)

URI_VPOOL_VARRAY_CAPACITY = '/block/vpools/{0}/varrays/{1}/capacity'
URI_BLOCK_EXPORTS_FOR_INITIATORS = '/block/exports?initiators={0}'
EXPORT_RETRY_COUNT = 5
MAX_NAME_LENGTH = 91


def retry_wrapper(func):
    def try_and_retry(*args, **kwargs):
        retry = False
        try:
            return func(*args, **kwargs)
        except coprhd_utils.CoprHdError as e:
            # if we got an http error and
            # the string contains 401 or if the string contains the word cookie
            if (e.err_code == coprhd_utils.CoprHdError.HTTP_ERR and
                (e.msg.find('401') != -1 or
                 e.msg.lower().find('cookie') != -1)):
                retry = True
                args[0].AUTHENTICATED = False
            else:
                exception_message = (_("\nCoprHD Exception: %(msg)s\n") %
                                     {'msg': e.msg})
                LOG.exception(exception_message)
                raise exception.VolumeBackendAPIException(
                    data=exception_message)
        except Exception as exc:
            exception_message = (_("\nGeneral Exception: %(exec_info)s\n") %
                                 {'exec_info':
                                  encodeutils.exception_to_unicode(exc)})
            LOG.exception(exception_message)
            raise exception.VolumeBackendAPIException(
                data=exception_message)

        if retry:
            return func(*args, **kwargs)

    return try_and_retry


class EMCCoprHDDriverCommon(object):

    OPENSTACK_TAG = 'OpenStack'

    def __init__(self, protocol, default_backend_name, configuration=None):
        self.AUTHENTICATED = False
        self.protocol = protocol
        self.configuration = configuration
        self.configuration.append_config_values(volume_opts)

        self.init_coprhd_api_components()
        self.verify_certificate()

        self.stats = {'driver_version': '3.0.0.0',
                      'free_capacity_gb': 'unknown',
                      'reserved_percentage': '0',
                      'storage_protocol': protocol,
                      'total_capacity_gb': 'unknown',
                      'vendor_name': 'CoprHD',
                      'volume_backend_name':
                      self.configuration.volume_backend_name or
                      default_backend_name}

    def init_coprhd_api_components(self):
        coprhd_utils.AUTH_TOKEN = None

        # instantiate coprhd api objects for later use
        self.volume_obj = coprhd_vol.Volume(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.exportgroup_obj = coprhd_eg.ExportGroup(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.host_obj = coprhd_host.Host(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.varray_obj = coprhd_varray.VirtualArray(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.snapshot_obj = coprhd_snap.Snapshot(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.consistencygroup_obj = coprhd_cg.ConsistencyGroup(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.tag_obj = coprhd_tag.Tag(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        self.network_obj = coprhd_network.Network(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

    def check_for_setup_error(self):
        # validate all of the coprhd_* configuration values
        if self.configuration.coprhd_hostname is None:
            message = _("coprhd_hostname is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_port is None:
            message = _("coprhd_port is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_username is None:
            message = _("coprhd_username is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_password is None:
            message = _("coprhd_password is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_tenant is None:
            message = _("coprhd_tenant is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_project is None:
            message = _("coprhd_project is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_varray is None:
            message = _("coprhd_varray is not set in cinder configuration")
            raise exception.VolumeBackendAPIException(data=message)

    def verify_certificate(self):
        coprhd_utils.VERIFY_CERT = False
        if (self.configuration.verify_server_certificate is False):
            coprhd_utils.VERIFY_CERT = False
        elif (self.configuration.verify_server_certificate is True and
              self.configuration.server_certificate_path is None):
            coprhd_utils.VERIFY_CERT = True
        elif (self.configuration.verify_server_certificate is True and
                self.configuration.server_certificate_path is not None):
            coprhd_utils.VERIFY_CERT = (
                self.configuration.server_certificate_path)

    def authenticate_user(self):
        # we should check to see if we are already authenticated before blindly
        # doing it again
        if self.AUTHENTICATED is False:
            obj = coprhd_auth.Authentication(
                self.configuration.coprhd_hostname,
                self.configuration.coprhd_port)

            username = self.configuration.coprhd_username
            password = self.configuration.coprhd_password

            coprhd_utils.AUTH_TOKEN = obj.authenticate_user(username,
                                                            password)
            self.AUTHENTICATED = True

    def create_volume(self, vol, driver, truncate_name=False):
        self.authenticate_user()
        name = self._get_resource_name(vol, truncate_name)
        size = int(vol['size']) * units.Gi

        vpool = self._get_vpool(vol)
        self.vpool = vpool['CoprHD:VPOOL']

        try:
            coprhd_cgid = None
            try:
                cgid = vol['consistencygroup_id']
                if cgid:
                    coprhd_cgid = self._get_coprhd_cgid(cgid)
            except KeyError:
                coprhd_cgid = None

            full_project_name = ("%s/%s" % (self.configuration.coprhd_tenant,
                                            self.configuration.coprhd_project))
            self.volume_obj.create(full_project_name, name, size,
                                   self.configuration.coprhd_varray,
                                   self.vpool,
                                   # no longer specified in volume creation
                                   sync=True,
                                   # no longer specified in volume creation
                                   consistencygroup=coprhd_cgid)
        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Volume %(name)s: create failed\n%(err)s") %
                              {'name': name, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Volume : %s creation failed") % name)
            self._raise_or_log_exception(
                e.err_code, coprhd_err_msg, log_err_msg)

    @retry_wrapper
    def create_consistencygroup(self, context, group, truncate_name=False):
        self.authenticate_user()
        name = self._get_resource_name(group, truncate_name)

        try:
            self.consistencygroup_obj.create(
                name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            cg_uri = self.consistencygroup_obj.consistencygroup_query(
                name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            self.set_tags_for_resource(
                coprhd_cg.ConsistencyGroup.URI_CONSISTENCY_GROUP_TAGS,
                cg_uri, group)

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Consistency Group %(name)s:"
                                " create failed\n%(err)s") %
                              {'name': name, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Consistency Group : %s creation failed") %
                           name)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def update_consistencygroup(self, group, add_volumes,
                                remove_volumes):
        self.authenticate_user()

        model_update = {'status': fields.ConsistencyGroupStatus.AVAILABLE}
        cg_uri = self._get_coprhd_cgid(group['id'])
        add_volnames = []
        remove_volnames = []

        try:
            if add_volumes:
                for vol in add_volumes:
                    vol_name = self._get_coprhd_volume_name(vol)
                    add_volnames.append(vol_name)

            if remove_volumes:
                for vol in remove_volumes:
                    vol_name = self._get_coprhd_volume_name(vol)
                    remove_volnames.append(vol_name)

            self.consistencygroup_obj.update(
                cg_uri,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant,
                add_volnames, remove_volnames, True)

            return model_update, None, None

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Consistency Group %(cg_uri)s:"
                                " update failed\n%(err)s") %
                              {'cg_uri': cg_uri, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Consistency Group : %s update failed") %
                           cg_uri)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def delete_consistencygroup(self, context, group, volumes,
                                truncate_name=False):
        self.authenticate_user()

        name = self._get_resource_name(group, truncate_name)
        volumes_model_update = []

        try:
            for vol in volumes:
                try:
                    vol_name = self._get_coprhd_volume_name(vol)
                    full_project_name = "%s/%s" % (
                        self.configuration.coprhd_tenant,
                        self.configuration.coprhd_project)

                    self.volume_obj.delete(full_project_name, vol_name,
                                           sync=True,
                                           force_delete=True)

                    update_item = {'id': vol['id'],
                                   'status':
                                   fields.ConsistencyGroupStatus.DELETED}
                    volumes_model_update.append(update_item)

                except exception.VolumeBackendAPIException:
                    update_item = {'id': vol['id'],
                                   'status': fields.ConsistencyGroupStatus.
                                   ERROR_DELETING}

                    volumes_model_update.append(update_item)

                    LOG.exception(_LE("Failed to delete the volume %s of CG."),
                                  vol['name'])

            self.consistencygroup_obj.delete(
                name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            model_update = {}
            model_update['status'] = group['status']

            return model_update, volumes_model_update

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Consistency Group %(name)s:"
                                " delete failed\n%(err)s") %
                              {'name': name, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Consistency Group : %s deletion failed") %
                           name)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def create_cgsnapshot(self, cgsnapshot, snapshots, truncate_name=False):
        self.authenticate_user()

        snapshots_model_update = []
        cgsnapshot_name = self._get_resource_name(cgsnapshot, truncate_name)
        cg_id = cgsnapshot['consistencygroup_id']
        cg_group = cgsnapshot.get('consistencygroup')
        cg_name = None
        coprhd_cgid = None

        if cg_id:
            coprhd_cgid = self._get_coprhd_cgid(cg_id)
            cg_name = self._get_consistencygroup_name(cg_group)

        LOG.info(_LI('Start to create cgsnapshot for consistency group'
                     ': %(group_name)s'),
                 {'group_name': cg_name})

        try:
            self.snapshot_obj.snapshot_create(
                'block',
                'consistency-groups',
                coprhd_cgid,
                cgsnapshot_name,
                False,
                True)

            for snapshot in snapshots:
                vol_id_of_snap = snapshot['volume_id']

                # Finding the volume in CoprHD for this volume id
                tagname = "OpenStack:id:" + vol_id_of_snap
                rslt = coprhd_utils.search_by_tag(
                    coprhd_vol.Volume.URI_SEARCH_VOLUMES_BY_TAG.format(
                        tagname),
                    self.configuration.coprhd_hostname,
                    self.configuration.coprhd_port)

                if not rslt:
                    continue

                vol_uri = rslt[0]

                snapshots_of_volume = self.snapshot_obj.snapshot_list_uri(
                    'block',
                    'volumes',
                    vol_uri)

                for snapUri in snapshots_of_volume:
                    snapshot_obj = self.snapshot_obj.snapshot_show_uri(
                        'block',
                        vol_uri,
                        snapUri['id'])

                    if not coprhd_utils.get_node_value(snapshot_obj,
                                                       'inactive'):

                        # Creating snapshot for a consistency group.
                        # When we create a consistency group snapshot on
                        # coprhd then each snapshot of volume in the
                        # consistencygroup will be given a subscript. Ex if
                        # the snapshot name is cgsnap1 and lets say there are
                        # three vols(a,b,c) in CG. Then the names of snapshots
                        # of the volumes in cg on coprhd end will be like
                        # cgsnap1-1 cgsnap1-2 cgsnap1-3. So, we list the
                        # snapshots of the volume under consideration and then
                        # split the name  using - from the ending as prefix
                        # and postfix. We compare the prefix to the cgsnapshot
                        # name and filter our the snapshots that correspond to
                        # the cgsnapshot

                        if '-' in snapshot_obj['name']:
                            (prefix, postfix) = snapshot_obj[
                                'name'].rsplit('-', 1)

                            if cgsnapshot_name == prefix:
                                self.set_tags_for_resource(
                                    coprhd_snap.Snapshot.
                                    URI_BLOCK_SNAPSHOTS_TAG,
                                    snapUri['id'],
                                    snapshot)

                        elif cgsnapshot_name == snapshot_obj['name']:
                            self.set_tags_for_resource(
                                coprhd_snap.Snapshot.URI_BLOCK_SNAPSHOTS_TAG,
                                snapUri['id'],
                                snapshot)

                snapshot['status'] = fields.SnapshotStatus.AVAILABLE
                snapshots_model_update.append(
                    {'id': snapshot['id'], 'status':
                     fields.SnapshotStatus.AVAILABLE})

            model_update = {'status': fields.ConsistencyGroupStatus.AVAILABLE}

            return model_update, snapshots_model_update

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Snapshot for Consistency Group %(cg_name)s:"
                                " create failed\n%(err)s") %
                              {'cg_name': cg_name,
                               'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Snapshot %(name)s for Consistency"
                               " Group: %(cg_name)s creation failed") %
                           {'cg_name': cg_name,
                            'name': cgsnapshot_name})
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def delete_cgsnapshot(self, cgsnapshot, snapshots, truncate_name=False):
        self.authenticate_user()

        cgsnapshot_id = cgsnapshot['id']
        cgsnapshot_name = self._get_resource_name(cgsnapshot, truncate_name)

        snapshots_model_update = []
        cg_id = cgsnapshot['consistencygroup_id']
        cg_group = cgsnapshot.get('consistencygroup')

        coprhd_cgid = self._get_coprhd_cgid(cg_id)
        cg_name = self._get_consistencygroup_name(cg_group)

        model_update = {}
        LOG.info(_LI('Delete cgsnapshot %(snap_name)s for consistency group: '
                     '%(group_name)s'), {'snap_name': cgsnapshot['name'],
                                         'group_name': cg_name})

        try:
            uri = None
            try:
                uri = self.snapshot_obj.snapshot_query('block',
                                                       'consistency-groups',
                                                       coprhd_cgid,
                                                       cgsnapshot_name + '-1')
            except coprhd_utils.CoprHdError as e:
                if e.err_code == coprhd_utils.CoprHdError.NOT_FOUND_ERR:
                    uri = self.snapshot_obj.snapshot_query(
                        'block',
                        'consistency-groups',
                        coprhd_cgid,
                        cgsnapshot_name)
            self.snapshot_obj.snapshot_delete_uri(
                'block',
                coprhd_cgid,
                uri,
                True,
                0)

            for snapshot in snapshots:
                snapshots_model_update.append(
                    {'id': snapshot['id'],
                     'status': fields.SnapshotStatus.DELETED})

            return model_update, snapshots_model_update

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Snapshot %(cgsnapshot_id)s: for"
                                " Consistency Group %(cg_name)s: delete"
                                " failed\n%(err)s") %
                              {'cgsnapshot_id': cgsnapshot_id,
                               'cg_name': cg_name,
                               'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Snapshot %(name)s for Consistency"
                               " Group: %(cg_name)s deletion failed") %
                           {'cg_name': cg_name,
                            'name': cgsnapshot_name})
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def set_volume_tags(self, vol, exempt_tags=None, truncate_name=False):
        if exempt_tags is None:
            exempt_tags = []

        self.authenticate_user()

        name = self._get_resource_name(vol, truncate_name)
        full_project_name = ("%s/%s" % (
            self.configuration.coprhd_tenant,
            self.configuration.coprhd_project))

        vol_uri = self.volume_obj.volume_query(full_project_name,
                                               name)

        self.set_tags_for_resource(
            coprhd_vol.Volume.URI_TAG_VOLUME, vol_uri, vol, exempt_tags)

    @retry_wrapper
    def set_host_tags(self, connector, truncate_name=False):

        self.authenticate_user()

        host_resource_id = self.host_obj.query_by_name(
            connector['host'], self.configuration.coprhd_tenant)
        add_tags = []
        tagname = self.OPENSTACK_TAG + connector['host']
        add_tags.append(tagname)

        try:
            self.tag_obj.tag_resource(
                coprhd_host.Host.URI_HOST_TAGS,
                host_resource_id,
                add_tags,
                None)
        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Adding %(tag)s: to host failed\n%(err)s") %
                              {'tag': add_tags, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Tag : %s addition failed") % add_tags)
            self._raise_or_log_exception(
                e.err_code, coprhd_err_msg, log_err_msg)

    @retry_wrapper
    def set_initiator_tags(self, host_name, resource_id, truncate_name=False):

        self.authenticate_user()

        add_tags = []
        tagname = self.OPENSTACK_TAG + host_name

        add_tags.append(tagname)

        try:
            self.tag_obj.tag_resource(
                coprhd_host.Host.URI_INITIATOR_TAGS,
                resource_id,
                add_tags,
                None)
        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Adding %(tag)s: to initiator failed\n%(err)s") %
                              {'tag': add_tags, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Tag : %s addition failed") % add_tags)
            self._raise_or_log_exception(
                e.err_code, coprhd_err_msg, log_err_msg)

    @retry_wrapper
    def set_tags_for_resource(self, uri, resource_id, resource,
                              exempt_tags=None):
        if exempt_tags is None:
            exempt_tags = []

        self.authenticate_user()

        # first, get the current tags that start with the OPENSTACK_TAG
        # eyecatcher
        formattedUri = uri.format(resource_id)
        remove_tags = []
        currentTags = self.tag_obj.list_tags(formattedUri)
        for cTag in currentTags:
            if cTag.startswith(self.OPENSTACK_TAG):
                remove_tags.append(cTag)

        try:
            if remove_tags:
                self.tag_obj.tag_resource(uri,
                                          resource_id,
                                          None,
                                          remove_tags)
        except coprhd_utils.CoprHdError as e:
            if e.err_code == coprhd_utils.CoprHdError.SOS_FAILURE_ERR:
                LOG.debug("CoprHdError adding the tag:\n %s", e.msg)

        # now add the tags for the resource
        add_tags = []
        # put all the openstack resource properties into the CoprHD resource

        try:
            for prop, value in vars(resource).items():
                try:
                    if prop in exempt_tags:
                        continue

                    if prop.startswith("_"):
                        prop = prop.replace("_", '', 1)

                    # don't put the status in, it's always the status before
                    # the current transaction
                    if ((not prop.startswith("status") and not
                         prop.startswith("obj_status") and
                         prop != "obj_volume") and value):
                        tag = ("%s:%s:%s" % (self.OPENSTACK_TAG, prop,
                                          six.text_type(value)))
                        if len(tag) > 128:
                            tag = tag[0:128]
                        add_tags.append(tag)
                except TypeError:
                    LOG.error(
                        _LE("Error tagging the resource property %s"), prop)
        except TypeError:
            LOG.error(_LE("Error tagging the resource properties"))

        try:
            self.tag_obj.tag_resource(
                uri,
                resource_id,
                add_tags,
                None)
        except coprhd_utils.CoprHdError as e:
            if e.err_code == coprhd_utils.CoprHdError.SOS_FAILURE_ERR:
                LOG.debug(
                    "Adding the tag failed. CoprHdError: %s", e.msg)

        return self.tag_obj.list_tags(formattedUri)

    @retry_wrapper
    def create_cloned_volume(self, vol, src_vref, truncate_name=False,
                             isVMAXSnapshot=False):
        """Creates a clone of the specified volume."""
        self.authenticate_user()

        name = self._get_resource_name(vol, truncate_name)
        srcname = self._get_coprhd_volume_name(src_vref)

        part_of_cg = False
        try:
            if src_vref['consistencygroup_id']:
                part_of_cg = True
        except AttributeError as e:
            try:
                if src_vref['cgsnapshot_id']:
                    part_of_cg = True
            except AttributeError as e:
                pass
        if part_of_cg:
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                _("Clone can't be taken individually on a volume"
                  " that is part of a Consistency Group"))
        try:
            (storageres_type,
             storageres_typename) = self.volume_obj.get_storageAttributes(
                srcname, None, None)

            resource_id = self.volume_obj.storage_resource_query(
                storageres_type,
                srcname,
                None,
                None,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            self.volume_obj.clone(
                name,
                resource_id,
                sync=True)

            full_project_name = "%s/%s" % (
                self.configuration.coprhd_tenant,
                self.configuration.coprhd_project)

            detachable = self.volume_obj.is_volume_detachable(
                full_project_name, name)
            LOG.debug("Is volume detachable : %s", detachable)

            # detach it from the source volume immediately after creation
            if detachable:
                self.volume_obj.volume_clone_detach(
                    "", full_project_name, name, True)

        except IndexError:
            LOG.exception(_LE("Volume clone detach returned empty task list"))

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Volume %(name)s: clone failed\n%(err)s") %
                              {'name': name, 'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Volume : {%s} clone failed") % name)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

        try:
            src_vol_size = src_vref['size']
        except AttributeError:
            src_vol_size = src_vref['volume_size']

        if isVMAXSnapshot:
            return

        if vol['size'] > src_vol_size:
            size_in_bytes = coprhd_utils.to_bytes("%sG" % vol['size'])
            try:
                self.volume_obj.expand(
                    ("%s/%s" % (self.configuration.coprhd_tenant,
                                self.configuration.coprhd_project)), name,
                    size_in_bytes,
                    True)
            except coprhd_utils.CoprHdError as e:
                coprhd_err_msg = (_("Volume %(volume_name)s: expand failed"
                                    "\n%(err)s") %
                                  {'volume_name': name,
                                   'err': six.text_type(e.msg)})

                log_err_msg = (_LE("Volume : %s expand failed") % name)
                self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                             log_err_msg)

    @retry_wrapper
    def expand_volume(self, vol, new_size):
        """expands the volume to new_size specified."""
        self.authenticate_user()

        volume_name = self._get_coprhd_volume_name(vol)
        size_in_bytes = coprhd_utils.to_bytes("%sG" % new_size)

        try:
            self.volume_obj.expand(
                ("%s/%s" % (self.configuration.coprhd_tenant,
                            self.configuration.coprhd_project)), volume_name,
                size_in_bytes,
                True)
        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Volume %(volume_name)s:"
                                " expand failed\n%(err)s") %
                              {'volume_name': volume_name,
                               'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Volume : %s expand failed") %
                           volume_name)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def create_volume_from_snapshot(self, snapshot, volume,
                                    truncate_name=False):
        """Creates volume from given snapshot ( snapshot clone to volume )."""
        self.authenticate_user()

        if self.configuration.coprhd_emulate_snapshot:
            self.create_cloned_volume(volume, snapshot, truncate_name)
            return

        if snapshot.get('cgsnapshot_id'):
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                _("Volume cannot be created individually from a snapshot "
                  "that is part of a Consistency Group"))

        src_snapshot_name = None
        src_vol_ref = snapshot['volume']
        new_volume_name = self._get_resource_name(volume, truncate_name)

        try:
            coprhd_vol_info = self._get_coprhd_volume_name(
                src_vol_ref, True)
            src_snapshot_name = self._get_coprhd_snapshot_name(
                snapshot, coprhd_vol_info['volume_uri'])

            (storageres_type,
             storageres_typename) = self.volume_obj.get_storageAttributes(
                coprhd_vol_info['volume_name'], None, src_snapshot_name)

            resource_id = self.volume_obj.storage_resource_query(
                storageres_type,
                coprhd_vol_info['volume_name'],
                None,
                src_snapshot_name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            self.volume_obj.clone(
                new_volume_name,
                resource_id,
                sync=True)

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Snapshot %(src_snapshot_name)s:"
                                " clone failed\n%(err)s") %
                              {'src_snapshot_name': src_snapshot_name,
                               'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Snapshot : %s clone failed") %
                           src_snapshot_name)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

        if volume['size'] > snapshot['volume_size']:
            size_in_bytes = coprhd_utils.to_bytes("%sG" % volume['size'])

            try:
                self.volume_obj.expand(
                    ("%s/%s" % (self.configuration.coprhd_tenant,
                                self.configuration.coprhd_project)),
                    new_volume_name, size_in_bytes, True)

            except coprhd_utils.CoprHdError as e:
                coprhd_err_msg = (_("Volume %(volume_name)s: expand failed"
                                    "\n%(err)s") %
                                  {'volume_name': new_volume_name,
                                   'err': six.text_type(e.msg)})

                log_err_msg = (_LE("Volume : %s expand failed") %
                               new_volume_name)
                self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                             log_err_msg)

    @retry_wrapper
    def delete_volume(self, vol, truncate_name=False):
        self.authenticate_user()
        name = self._get_coprhd_volume_name(vol, False, truncate_name)

        try:
            full_project_name = ("%s/%s" % (
                self.configuration.coprhd_tenant,
                self.configuration.coprhd_project))
            self.volume_obj.delete(full_project_name, name, sync=True)
        except coprhd_utils.CoprHdError as e:
            if e.err_code == coprhd_utils.CoprHdError.NOT_FOUND_ERR:
                LOG.info(_LI(
                    "Volume %s"
                    " no longer exists; volume deletion is"
                    " considered successful."), name)
            else:
                coprhd_err_msg = (_("Volume %(name)s: delete failed"
                                    "\n%(err)s") %
                                  {'name': name, 'err': six.text_type(e.msg)})

                log_err_msg = (_LE("Volume : %s delete failed") % name)
                self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                             log_err_msg)

    @retry_wrapper
    def create_snapshot(self, snapshot, truncate_name=False):
        self.authenticate_user()

        volume = snapshot['volume']

        try:
            if volume['consistencygroup_id']:
                raise coprhd_utils.CoprHdError(
                    coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                    _("Snapshot can't be taken individually on a volume"
                      " that is part of a Consistency Group"))
        except KeyError:
            LOG.info(_LI("No Consistency Group associated with the volume"))

        if self.configuration.coprhd_emulate_snapshot:
            self.create_cloned_volume(snapshot, volume, truncate_name, True)
            self.set_volume_tags(
                snapshot, ['_volume', '_obj_volume_type'], truncate_name)
            return

        try:
            snapshotname = self._get_resource_name(snapshot, truncate_name)
            vol = snapshot['volume']

            volumename = self._get_coprhd_volume_name(vol)
            projectname = self.configuration.coprhd_project
            tenantname = self.configuration.coprhd_tenant
            storageres_type = 'block'
            storageres_typename = 'volumes'
            resource_uri = self.snapshot_obj.storage_resource_query(
                storageres_type,
                volume_name=volumename,
                cg_name=None,
                project=projectname,
                tenant=tenantname)
            inactive = False
            sync = True
            self.snapshot_obj.snapshot_create(
                storageres_type,
                storageres_typename,
                resource_uri,
                snapshotname,
                inactive,
                sync)

            snapshot_uri = self.snapshot_obj.snapshot_query(
                storageres_type,
                storageres_typename,
                resource_uri,
                snapshotname)

            self.set_tags_for_resource(
                coprhd_snap.Snapshot.URI_BLOCK_SNAPSHOTS_TAG,
                snapshot_uri, snapshot, ['_volume'])

        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Snapshot: %(snapshotname)s, create failed"
                                "\n%(err)s") % {'snapshotname': snapshotname,
                                                'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Snapshot : %s create failed") % snapshotname)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def delete_snapshot(self, snapshot):
        self.authenticate_user()

        vol = snapshot['volume']

        try:
            if vol['consistencygroup_id']:
                raise coprhd_utils.CoprHdError(
                    coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                    _("Snapshot delete can't be done individually on a volume"
                      " that is part of a Consistency Group"))
        except KeyError:
            LOG.info(_LI("No Consistency Group associated with the volume"))

        if self.configuration.coprhd_emulate_snapshot:
            self.delete_volume(snapshot)
            return

        snapshotname = None
        try:
            volumename = self._get_coprhd_volume_name(vol)
            projectname = self.configuration.coprhd_project
            tenantname = self.configuration.coprhd_tenant
            storageres_type = 'block'
            storageres_typename = 'volumes'
            resource_uri = self.snapshot_obj.storage_resource_query(
                storageres_type,
                volume_name=volumename,
                cg_name=None,
                project=projectname,
                tenant=tenantname)
            if resource_uri is None:
                LOG.info(_LI(
                    "Snapshot %s"
                    " is not found; snapshot deletion"
                    " is considered successful."), snapshotname)
            else:
                snapshotname = self._get_coprhd_snapshot_name(
                    snapshot, resource_uri)

                self.snapshot_obj.snapshot_delete(
                    storageres_type,
                    storageres_typename,
                    resource_uri,
                    snapshotname,
                    sync=True)
        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Snapshot %s : Delete Failed\n") %
                              snapshotname)

            log_err_msg = (_LE("Snapshot : %s delete failed") % snapshotname)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    @retry_wrapper
    def initialize_connection(self, volume, protocol, initiator_ports,
                              initiator_nodes,
                              connector):
        """Makes REST API call and retrieves project details based on UUID.

        :param volume: Name of the volume to attach
        :param protocol: Protocol ('fc', 'iscsi' or 'scaleio')
        :param initiator_ports: Host initiator ports
        :param initiator_nodes: Host initiator nodes
        :param connector: connector information

        :returns: itls
        """
        try:
            self.authenticate_user()
            volumename = self._get_coprhd_volume_name(volume)

            # When a newly created LPAR is registered in ViPR
            # its virtual initiators are not logged into the
            # network until it is booted, so we see the status
            # of the physical initiators which map to the virtual
            # initiators and add the virtual initiators to
            # the network if the corresponding physical initiators
            # are also logged in.

            self._add_virtual_initiators_to_network(connector)

            foundgroupdetails = self._find_exportgroup(initiator_ports)
            if foundgroupdetails:
                # Check if this export group has same, less or more than
                # requested initiators.
                initiators = foundgroupdetails['initiators']
                if len(initiators) > 0:
                    initiators_in_eg = set()
                    for initiator in initiators:
                        initiators_in_eg.add(initiator['initiator_port'])
                    if initiators_in_eg == set(initiator_ports):
                        self._handle_eg_with_same_initiators(volumename,
                                                             foundgroupdetails)

                    elif initiators_in_eg > set(initiator_ports):
                        self._handle_eg_with_more_initiators(volumename,
                                                             foundgroupdetails,
                                                             initiator_ports,
                                                             connector)

                    elif initiators_in_eg < set(initiator_ports):
                        self._handle_eg_with_less_initiators(volumename,
                                                             foundgroupdetails,
                                                             initiator_ports,
                                                             connector,
                                                             protocol)
            else:
                LOG.debug("No matching export group found")
                # See if any host with the given initiators exists in CoprHD
                foundhostdetails = self._find_host(initiator_ports)
                if foundhostdetails:
                    # Check if this host has same, less or more than requested
                    # initiators
                    initiators = self.host_obj.list_initiators(
                        foundhostdetails['id'],
                        self.configuration.coprhd_tenant)
                    if len(initiators) > 0:
                        existing_initiators_host = set()
                        for initiator in initiators:
                            existing_initiators_host.add(initiator['name'])
                        if existing_initiators_host == set(initiator_ports):
                            self._handle_host_with_same_initiators(
                                foundhostdetails, volumename)

                        elif existing_initiators_host > set(initiator_ports):
                            self._handle_host_with_more_initiators(
                                foundhostdetails, initiator_ports, connector, volumename)

                        elif existing_initiators_host < set(initiator_ports):
                            self._handle_host_with_less_initiators(
                                connector, foundhostdetails, protocol, volumename)

                        elif existing_initiators_host & set(initiator_ports):
                            self._handle_host_with_some_initiators(
                                connector, foundhostdetails, protocol, initiator_ports, volumename)
                else:
                    self._create_host_and_eg(connector, protocol,
                                             initiator_ports,
                                             volumename)

            if self.is_auto_zoning_configured():
                # CoprHD will perform the zoning. Hence setting the zoning_mode
                # to a value other than 'fabric'
                self.configuration.zoning_mode = "CoprHD"
            return self._find_device_info(volume, initiator_ports)
        except coprhd_utils.CoprHdError as e:
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                (_("Attach volume (%(name)s) to host"
                   " (%(hostname)s) initiator (%(initiatorport)s)"
                   " failed:\n%(err)s") %
                 {'name': self._get_coprhd_volume_name(
                     volume),
                  'hostname': connector['host'],
                  'initiatorport': initiator_ports[0],
                  'err': six.text_type(e.msg)})
            )

    @retry_wrapper
    def terminate_connection(self, volume, protocol, initiator_ports,
                             connector):
        try:
            self.authenticate_user()
            volumename = self._get_coprhd_volume_name(volume)
            full_project_name = ("%s/%s" % (self.configuration.coprhd_tenant,
                                            self.configuration.coprhd_project))
            voldetails = self.volume_obj.show(full_project_name, volumename)
            volid = voldetails['id']

            # find the exportgroups
            exports = self.volume_obj.get_exports_by_uri(volid)
            exportgroups = set()
            itls = exports['itl']
            for itl in itls:
                itl_port = itl['initiator']['port']
                if itl_port in initiator_ports:
                    exportgroups.add(itl['export']['id'])

            for exportgroup in exportgroups:
                self.exportgroup_obj.exportgroup_remove_volumes_by_uri(
                    exportgroup,
                    volid,
                    self.configuration.coprhd_tenant,
                    True,
                    None,
                    None,
                    None)
            else:
                LOG.info(_LI(
                    "No export group found for the host: %s"
                    "; this is considered already detached."),
                    connector['host'])

            return itls

        except coprhd_utils.CoprHdError as e:
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                (_("Detaching volume %(volumename)s from host"
                   " %(hostname)s failed: %(err)s") %
                 {'volumename': volumename,
                  'hostname': connector['host'],
                  'err': six.text_type(e.msg)})
            )

    @retry_wrapper
    def _find_device_info(self, volume, initiator_ports):
        """Returns device_info in list of itls having the matched initiator.

        (there could be multiple targets, hence a list):
                [
                 {
                  "hlu":9,
                  "initiator":{...,"port":"20:00:00:25:B5:49:00:22"},
                  "export":{...},
                  "device":{...,"wwn":"600601602B802D00B62236585D0BE311"},
                  "target":{...,"port":"50:06:01:6A:46:E0:72:EF"},
                  "san_zone_name":"..."
                 },
                 {
                  "hlu":9,
                  "initiator":{...,"port":"20:00:00:25:B5:49:00:22"},
                  "export":{...},
                  "device":{...,"wwn":"600601602B802D00B62236585D0BE311"},
                  "target":{...,"port":"50:06:01:62:46:E0:72:EF"},
                  "san_zone_name":"..."
                 }
                ]
        """
        volumename = self._get_coprhd_volume_name(volume)
        full_project_name = ("%s/%s" % (self.configuration.coprhd_tenant,
                                        self.configuration.coprhd_project))
        vol_uri = self.volume_obj.volume_query(full_project_name, volumename)

        # The itl info shall be available at the first try since now export is
        # a synchronous call.  We are trying a few more times to accommodate
        # any delay on filling in the itl info after the export task is
        # completed.

        itls = []
        for x in range(MAX_RETRIES):
            exports = self.volume_obj.get_exports_by_uri(vol_uri)
            LOG.debug("Volume exports: ")
            LOG.info(vol_uri)
            LOG.debug(exports)
            for itl in exports['itl']:
                itl_port = itl['initiator']['port']
                if itl_port in initiator_ports:
                    found_device_number = itl['hlu']
                    if (found_device_number is not None and
                            found_device_number != '-1'):
                        # 0 is a valid number for found_device_number.
                        # Only loop if it is None or -1
                        LOG.debug("Found Device Number: %s",
                                  found_device_number)
                        itls.append(itl)

            if itls:
                break
            else:
                LOG.debug("Device Number not found yet."
                          " Retrying after 10 seconds...")
                eventlet.sleep(INTERVAL_10_SEC)

        if itls is None:
            # No device number found after 10 tries; return an empty itl
            LOG.info(_LI(
                "No device number has been found after 10 tries; "
                "this likely indicates an unsuccessful attach of "
                "volume volumename=%(volumename)s to"
                " initiator  initiator_ports=%(initiator_ports)s"),
                {'volumename': volumename,
                    'initiator_ports': initiator_ports})

        return itls

    def _get_coprhd_cgid(self, cgid):
        tagname = self.OPENSTACK_TAG + ":id:" + cgid
        rslt = coprhd_utils.search_by_tag(
            coprhd_cg.ConsistencyGroup.URI_SEARCH_CONSISTENCY_GROUPS_BY_TAG.
            format(tagname),
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        # if the result is empty, then search with the tagname as
        # "OpenStack:obj_id" the openstack attribute for id can be obj_id
        # instead of id. this depends on the version
        if rslt is None or len(rslt) == 0:
            tagname = self.OPENSTACK_TAG + ":obj_id:" + cgid
            rslt = coprhd_utils.search_by_tag(
                coprhd_cg.ConsistencyGroup
                .URI_SEARCH_CONSISTENCY_GROUPS_BY_TAG.
                format(tagname),
                self.configuration.coprhd_hostname,
                self.configuration.coprhd_port)

        if len(rslt) > 0:
            rslt_cg = self.consistencygroup_obj.show(
                rslt[0],
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)
            return rslt_cg['id']
        else:
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.NOT_FOUND_ERR,
                (_("Consistency Group %s not found") % cgid))

    def _get_consistencygroup_name(self, consisgrp):
        return consisgrp['name']

    def _get_coprhd_snapshot_name(self, snapshot, resUri):
        tagname = self.OPENSTACK_TAG + ":id:" + snapshot['id']
        rslt = coprhd_utils.search_by_tag(
            coprhd_snap.Snapshot.URI_SEARCH_SNAPSHOT_BY_TAG.format(tagname),
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        # if the result is empty, then search with the tagname
        # as "OpenStack:obj_id"
        # as snapshots will be having the obj_id instead of just id.
        if not rslt:
            tagname = self.OPENSTACK_TAG + ":obj_id:" + snapshot['id']
            rslt = coprhd_utils.search_by_tag(
                coprhd_snap.Snapshot.URI_SEARCH_SNAPSHOT_BY_TAG.format(
                    tagname),
                self.configuration.coprhd_hostname,
                self.configuration.coprhd_port)

        if rslt is None or len(rslt) == 0:
            return snapshot['name']
        else:
            rslt_snap = self.snapshot_obj.snapshot_show_uri(
                'block',
                resUri,
                rslt[0])
            return rslt_snap['name']

    def _get_coprhd_volume_name(self, vol, verbose=False,
                                truncate_name=False):
        tagname = self.OPENSTACK_TAG + ":id:" + vol['id']
        rslt = coprhd_utils.search_by_tag(
            coprhd_vol.Volume.URI_SEARCH_VOLUMES_BY_TAG.format(tagname),
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port)

        # if the result is empty, then search with the tagname
        # as "OpenStack:obj_id"
        # as snapshots will be having the obj_id instead of just id.
        if len(rslt) == 0:
            tagname = self.OPENSTACK_TAG + ":obj_id:" + vol['id']
            rslt = coprhd_utils.search_by_tag(
                coprhd_vol.Volume.URI_SEARCH_VOLUMES_BY_TAG.format(tagname),
                self.configuration.coprhd_hostname,
                self.configuration.coprhd_port)

        if len(rslt) > 0:
            rslt_vol = self.volume_obj.show_by_uri(rslt[0])

            if verbose is True:
                return {'volume_name': rslt_vol['name'], 'volume_uri': rslt[0]}
            else:
                return rslt_vol['name']

        if truncate_name and len(vol['display_name']) > 31:
            name = self._id_to_base64(vol.id)
            return name
        else:
            return vol['display_name']

    def _get_resource_name(self, resource, truncate_name=False):
        name = resource.get('display_name', None)

        if not name:
            name = resource['name']

        if truncate_name and len(name) > 31:
            name = self._id_to_base64(resource.id)
            return name

        elif truncate_name:
            return name
        elif len(name) > MAX_NAME_LENGTH:
            return name[0:91] + "-" + resource['id']
        else:
            return name + "-" + resource['id']

    def _get_vpool(self, volume):
        vpool = {}
        ctxt = context.get_admin_context()
        type_id = volume['volume_type_id']
        if type_id is not None:
            volume_type = volume_types.get_volume_type(ctxt, type_id)
            specs = volume_type.get('extra_specs')
            for key, value in specs.items():
                vpool[key] = value

        return vpool

    def _id_to_base64(self, id):
        # Base64 encode the id to get a volume name less than 32 characters due
        # to ScaleIO limitation.
        name = six.text_type(id).replace("-", "")
        try:
            name = base64.b16decode(name.upper())
        except (TypeError, binascii.Error):
            pass
        encoded_name = name
        if isinstance(encoded_name, six.text_type):
            encoded_name = encoded_name.encode('utf-8')
        encoded_name = base64.b64encode(encoded_name)
        if six.PY3:
            encoded_name = encoded_name.decode('ascii')
        LOG.debug("Converted id %(id)s to scaleio name %(name)s.",
                  {'id': id, 'name': encoded_name})
        return encoded_name

    def _raise_or_log_exception(self, err_code, coprhd_err_msg, log_err_msg):

        if err_code == coprhd_utils.CoprHdError.SOS_FAILURE_ERR:
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                coprhd_err_msg)
        else:
            with excutils.save_and_reraise_exception():
                LOG.exception(log_err_msg)

    @retry_wrapper
    def _find_exportgroup(self, initiator_ports):
        """Find exportgroup having same, more or less than given initiators."""

        grouplist = self.exportgroup_obj.exportgroup_list(
            self.configuration.coprhd_project,
            self.configuration.coprhd_tenant)
        export_group = None
        found_eg_with_same_initiators = None
        found_eg_with_less_initiators = None
        found_eg_with_more_initiators = None
        for groupid in grouplist:
            groupdetails = self.exportgroup_obj.exportgroup_show(
                groupid,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)
            if groupdetails is not None:

                if groupdetails['inactive']:
                    continue
                initiators = groupdetails['initiators']

                if len(initiators) > 0:
                    initiators_in_eg = set()
                    for initiator in initiators:
                        initiators_in_eg.add(initiator['initiator_port'])

                    if initiators_in_eg == set(initiator_ports):
                        # Check the associated varray
                        found_eg_with_same_initiators = self._check_associated_varray(
                            groupdetails)
                        if found_eg_with_same_initiators:
                            LOG.debug(
                                "Found exportgroup %s",
                                found_eg_with_same_initiators['name'])
                            export_group = found_eg_with_same_initiators

                    elif initiators_in_eg > set(initiator_ports):
                        # Check the associated varray
                        found_eg_with_more_initiators = self._check_associated_varray(
                            groupdetails)
                        if found_eg_with_more_initiators:
                            LOG.debug(
                                "Found exportgroup having more than required initiators"
                                " ports %s", found_eg_with_more_initiators['name'])
                            export_group = found_eg_with_more_initiators

                    elif initiators_in_eg < set(initiator_ports):
                        # Check the associated varray
                        found_eg_with_less_initiators = self._check_associated_varray(
                            groupdetails)
                        if found_eg_with_less_initiators:
                            LOG.debug(
                                "Found exportgroup having less than required"
                                " initiators ports %s",
                                found_eg_with_less_initiators['name'])
                            export_group = found_eg_with_less_initiators

        return export_group

    @retry_wrapper
    def _find_host(self, initiator_ports):
        """Find host having same, more or less than given initiators."""

        hosts = self.host_obj.list_all(self.configuration.coprhd_tenant)
        found_host_with_same_initiators = None
        found_host_with_less_initiators = None
        found_host_with_more_initiators = None
        found_host_with_some_initiators = None

        for host in hosts:
            initiators = self.host_obj.list_initiators(host['id'],
                                                       self.configuration.coprhd_tenant)

            if len(initiators) > 0:
                initiators_in_eg = set()
                for initiator in initiators:
                    initiators_in_eg.add(initiator['name'])
                if initiators_in_eg == set(initiator_ports):
                    found_host_with_same_initiators = host
                elif initiators_in_eg < set(initiator_ports):
                    found_host_with_less_initiators = host
                elif initiators_in_eg > set(initiator_ports):
                    found_host_with_more_initiators = host
                elif initiators_in_eg & set(initiator_ports):
                    # Host has some of the requested initiators
                    found_host_with_some_initiators = host
                else:
                    # No host containing ANY of the requested initiators found
                    continue
        if found_host_with_same_initiators:
            return found_host_with_same_initiators
        elif found_host_with_more_initiators:
            return found_host_with_more_initiators
        elif found_host_with_less_initiators:
            return found_host_with_less_initiators
        elif found_host_with_some_initiators:
            return found_host_with_some_initiators
        else:
            return None

    @retry_wrapper
    def get_exports_count_by_initiators(self, initiator_ports):
        """Fetches ITL map for a given list of initiator ports."""
        comma_delimited_initiator_list = ",".join(initiator_ports)
        (s, h) = coprhd_utils.service_json_request(
            self.configuration.coprhd_hostname,
            self.configuration.coprhd_port, "GET",
            URI_BLOCK_EXPORTS_FOR_INITIATORS.format(
                comma_delimited_initiator_list),
            None)

        export_itl_maps = coprhd_utils.json_decode(s)

        if export_itl_maps is None:
            return 0

        itls = export_itl_maps['itl']
        return itls.__len__()

    @retry_wrapper
    def update_volume_stats(self):
        """Retrieve stats info."""
        LOG.debug("Updating volume stats")

        self.authenticate_user()

        try:
            self.stats['consistencygroup_support'] = 'True'
            vols = self.volume_obj.list_volumes(
                self.configuration.coprhd_tenant +
                "/" +
                self.configuration.coprhd_project)

            vpairs = set()
            if len(vols) > 0:
                for vol in vols:
                    if vol:
                        vpair = (vol["vpool"]["id"], vol["varray"]["id"])
                        if vpair not in vpairs:
                            vpairs.add(vpair)

            if len(vpairs) > 0:
                free_gb = 0.0
                used_gb = 0.0

                for vpair in vpairs:
                    if vpair:
                        (s, h) = coprhd_utils.service_json_request(
                            self.configuration.coprhd_hostname,
                            self.configuration.coprhd_port,
                            "GET",
                            URI_VPOOL_VARRAY_CAPACITY.format(vpair[0],
                                                             vpair[1]),
                            body=None)
                        capacity = coprhd_utils.json_decode(s)

                        free_gb += float(capacity["free_gb"])
                        used_gb += float(capacity["used_gb"])

                self.stats['free_capacity_gb'] = free_gb
                self.stats['total_capacity_gb'] = free_gb + used_gb
                self.stats['reserved_percentage'] = (
                    self.configuration.reserved_percentage)

            return self.stats

        except coprhd_utils.CoprHdError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Update volume stats failed"))

    @retry_wrapper
    def retype(self, ctxt, volume, new_type, diff, host):
        """changes the vpool type."""
        self.authenticate_user()

        volume_name = self._get_coprhd_volume_name(volume)
        vpool_name = new_type['extra_specs']['CoprHD:VPOOL']

        try:
            full_project_name = "%s/%s" % (
                self.configuration.coprhd_tenant,
                self.configuration.coprhd_project)

            task = self.volume_obj.update(
                full_project_name,
                volume_name,
                vpool_name)

            self.volume_obj.check_for_sync(task['task'][0], True)
            return True
        except coprhd_utils.CoprHdError as e:
            coprhd_err_msg = (_("Volume %(volume_name)s: update failed"
                                "\n%(err)s") % {'volume_name': volume_name,
                                                'err': six.text_type(e.msg)})

            log_err_msg = (_LE("Volume : %s type update failed") %
                           volume_name)
            self._raise_or_log_exception(e.err_code, coprhd_err_msg,
                                         log_err_msg)

    def _get_formatted_virt_inits(self, phy_to_virt_dictionay):
        """Formats the initiators

        :param phy_to_virt_dictionay: Physical to virtual initiator mapping
        :returns: List of formatted initiator ports
        """
        formatted_virt_inits = []
        for phy, virt_list in phy_to_virt_dictionay.items():
            for item in virt_list:
                virt_init = ':'.join(re.findall(
                    '..', item)).upper()   # Add ":" every two digits
                formatted_virt_inits.append(virt_init)
        return formatted_virt_inits

    def is_auto_zoning_configured(self):
        """Determines SAN zoning type configured in the varray
        :returns: 'True' or 'False'
        """

        self.authenticate_user()
        varray_name = self.configuration.coprhd_varray
        varray_id = self.varray_obj.varray_query(varray_name)
        varray_details = self.varray_obj.varray_show(varray_id)
        return varray_details['auto_san_zoning']

    def get_init_ports_uri_list(self, all_initiators, initiator_ports):
        """Gets the initiator uris

        :param all_initiators: List of all initiators belonging to the resource
        :param initiator_ports: Subset of initiators whose uris are needed
        :returns: List of uris
        """
        init_ports_uri_list = []

        for initiator in all_initiators:
            if initiator['name'] in initiator_ports:
                init_ports_uri_list.append(initiator['id'])

        return init_ports_uri_list

    def add_initiator_pairs_to_host(self, virt_inits_pair_wise,
                                    host_name, protocol):
        """Adds initiators(pair-wise) to the host

        :param virt_inits_pair_wise: List of all initiators
        :param host_name: Name of the host
        :param protocol: Protocol
        """
        for i in range(0, (len(virt_inits_pair_wise) - 1), 2):
            # Since for 'iSCSI' & 'scaleio' protocols, only
            # iqn or ports information is provided
            if protocol in ('iSCSI', 'scaleio'):
                return
            else:
                first_init_node = virt_inits_pair_wise[i]
                second_init_node = virt_inits_pair_wise[i + 1]
            try:
                self.host_obj.create_paired_initiators_for_host(
                    host_name,
                    protocol,
                    first_init_node,
                    virt_inits_pair_wise[i],
                    second_init_node,
                    virt_inits_pair_wise[i + 1],
                    self.configuration.coprhd_tenant)
                LOG.info(_(
                    "Initiator v1=%(v1)s and Initiator v2=%(v2)s"
                    " added to host  v3=%(v3)s") %
                    {'v1': virt_inits_pair_wise[i],
                     'v2': virt_inits_pair_wise[i + 1],
                     'v3': host_name})
                # Set tags for the first newly added initiator
                # to the host
                first_initiator_resource_id = (
                    self.host_obj.query_initiator_by_name(
                        virt_inits_pair_wise[i],
                        host_name,
                        self.configuration.coprhd_tenant))

                self.set_initiator_tags(host_name, first_initiator_resource_id)

                '''Set tags for the second newly added initiator
                 to the host'''
                second_initiator_resource_id = (
                    self.host_obj.query_initiator_by_name(
                        virt_inits_pair_wise[i + 1],
                        host_name,
                        self.configuration.coprhd_tenant))

                self.set_initiator_tags(
                    host_name, second_initiator_resource_id)

            except coprhd_utils.CoprHdError as e:
                pass
        return

    def _fetch_volume_info(self):
        """Returns a list of all the volumes
        which are present under a given varray"""

        varray = self.configuration.coprhd_varray
        varray_uri = self.varray_obj.varray_query(varray)

        project = self.configuration.coprhd_project
        list_volumes = self.volume_obj.list_volumes(project)

        list_result = [{'name': volume['name'],
                        'status': 'available',
                        'size': int(float(volume['requested_capacity_gb'])),
                        'restricted_metadata':
                        {'vdisk_id': volume['native_id'],
                         'vdisk_name': volume['device_label'],
                         'vdisk_uid': volume['wwn']},
                        }
                       for volume in list_volumes
                       if volume['varray']['id'] == varray_uri]

        return list_result

    @retry_wrapper
    def get_volume_info(self, vol_refs, filter_set):
        """Return volume information from the backend.

        :param vol_refs: Dictionary containing k2udid,
        pg83NAA and uuid.
        :param filter_set: Dictionary containing data
        on which volumes would be filtered.
        :returns Volume details in JSON response payload
        """

        self.authenticate_user()

        volume_list = self._fetch_volume_info()
        full_project_name = ("%s/%s" % (self.configuration.coprhd_tenant,
                                        self.configuration.coprhd_project))

        filtered_list = []

        for volume in volume_list:
            vol_uri = self.volume_obj.volume_query(
                full_project_name, volume['name'])
            exports = self.volume_obj.get_exports_by_uri(vol_uri)
            storage_pool = self.volume_obj.get_volume_storage_pool(vol_uri)
            volume['storage_pool'] = storage_pool['storage_pool']['name']
            volume['is_mapped'] = False  # default
            if exports['itl']:
                volume['is_mapped'] = True
                volume['status'] = 'in-use'
                volume['support'] = {
                    'status': 'not_supported',
                    'reasons': ['attached']}
                volume['mapped_wwpns'] = []
                target_wwn = []
                host_name = []
                target_LUN = []
                for itl in exports['itl']:
                    initiator_ports = itl['initiator']['port'].replace(":", "")
                    volume['mapped_wwpns'].append(initiator_ports)
                    try:
                        storage_wwpns = itl['target']['port'].replace(":", "")
                        target_wwn.append(storage_wwpns)
                    except KeyError:
                        pass
                host_names = itl['export']['name']
                host_name.append(host_names)
                target_LUNs = itl['hlu']
                target_LUN.append(target_LUNs)
                connection_info = {}
                connection_info['source_wwn'] = volume['mapped_wwpns']
                connection_info['target_wwn'] = target_wwn
                connection_info['host_name'] = host_name
                connection_info['target_LUN'] = target_LUN
                volume['connection_info'] = connection_info
                itl = discovery_driver.ITLObject(
                    initiator_ports, storage_wwpns, target_LUNs)
                volume['itl_list'] = []
                volume['itl_list'].append(itl)
                if filter_set and (
                        filter_set & set(
                            volume['mapped_wwpns'])):
                        filtered_list.append(volume)
            else:
                volume['support'] = {'status': 'supported'}

        if filter_set is not None:
            return filtered_list
        else:
            return volume_list

    def _handle_eg_with_same_initiators(self, volumename, foundgroupdetails):
        """Exports volume to an export group

        :param volumename: Name of volume to be exported
        :param foundgroupdetails: Object containing details of export group
        """

        # Found an export group having exactly the same
        # initiators, add volumes to it.
        # No tags would be set on initiators or Hosts.

        LOG.debug(
            "adding the volume to the exportgroup : %s",
            foundgroupdetails['name'])

        self._add_volume_to_eg(foundgroupdetails['name'], volumename)

        return

    def _handle_eg_with_more_initiators(self, volumename, foundgroupdetails,
                                        initiator_ports, connector):
        """Exports volume to a newly created EG

        :param volumename: Name of volume to be exported
        :param foundgroupdetails:Contains details of export group
        :param initiator_ports: Details of initiator ports
        :param connector: connector information
        """
        # In this case, initiators coming from the
        # connector are less than ones present in the EG.
        # Now we create a new export group of Initiator type
        # and add the requested initiator ports to it.
        # First we fetch the initiator uris from the existing
        # export group.
        # Tags should not be set on initiators because they
        # already existed in ViPR

        init_ports_uri_list = self.get_init_ports_uri_list(
            foundgroupdetails['initiators'], initiator_ports)

        # Create a unique name
        exp_group_name = self._get_unique_exportgroup_name(connector)
        # First create an empty export group of type Initiator
        self._create_export_group(exp_group_name,
                                  'Initiator')

        # Update the above export group with requested
        # Initiators.
        self._update_export_group(exp_group_name,
                                  "initiator_changes",
                                  init_ports_uri_list)

        LOG.debug("adding the volume to the exportgroup : %s",
                  exp_group_name)
        self._add_volume_to_eg(exp_group_name, volumename)

        return

    def _handle_eg_with_less_initiators(self, volumename, foundgroupdetails,
                                        initiator_ports, connector,
                                        protocol):
        """Updates the initiators of existing EG

        :param volumename: Name of volume to be exported
        :param foundgroupdetails:Contains details of export group
        :param initiator_ports: Details of initiator ports
        :param connector: connector information
        """
        # In this case, initiators coming from
        # connector are more than initiators present in EG.
        # Found an export group with less than requested
        # initiators. We fetch the host from that export group
        # & update the host with the remaining initiators.
        # Then update the export group with those initiators.
        # Get the host name from the foundgroupdetails
        # Tags should be set on the initiators which are
        # being newly added in ViPR from Cinder Driver.

        export_group_host_name = foundgroupdetails['initiators'][0]['hostname']

        virt_inits_pair_wise = (
            self._get_formatted_virt_inits(
                connector['phy_to_virt_initiators']))
        # Add initiators to host and set tags for them

        self.add_initiator_pairs_to_host(
            virt_inits_pair_wise,
            export_group_host_name, protocol)
        initiators = self.host_obj.list_initiators(
            export_group_host_name,
            self.configuration.coprhd_tenant)

        init_ports_uri_list = self.get_init_ports_uri_list(
            initiators, initiator_ports)

        try:
            self._update_export_group(foundgroupdetails['name'],
                                      "initiator_changes",
                                      init_ports_uri_list)

        except SOSError as e:
            raise coprhd_utils.CoprHdError(
                coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                (_("Export group (%(name)s) update"
                   " failed:\n%(err)s") %
                 {'name': foundgroupdetails['name'],
                  'err': six.text_type(e.msg)}))
        LOG.debug(
            "adding the volume to the exportgroup : %s",
            foundgroupdetails['name'])
        self._add_volume_to_eg(foundgroupdetails['name'], volumename)

        return

    def _handle_host_with_same_initiators(self, foundhostdetails, volumename):
        """Creates export group for found Host

        :param foundhostdetails: Details of the found host
        :param volumename: Name of the volume
        """
        # Found host having exactly the same initiators,
        # hence go ahead and create export group for it.
        # No tags should be set in this case.

        newexpgroupname = self._get_unique_exportgroup_name(foundhostdetails)
        self._create_export_group(newexpgroupname,
                                  'Host',
                                  foundhostdetails['name'])

        LOG.debug(
            "adding the volume to the exportgroup : %s",
            newexpgroupname)
        self._add_volume_to_eg(newexpgroupname, volumename)

        return

    def _handle_host_with_more_initiators(
            self,
            foundhostdetails,
            initiator_ports,
            connector,
            volumename):
        """Creates export group for found Host with more initiators

        :param foundhostdetails: Details of the found host
        :param initiator_ports: Set of initiator ports
        :param volumename: Name of the volume
        """
        # Found a host having more than the requested
        # initiators. Now we go ahead and create an export
        # group of Initiator type and add only the
        # requested initiator ports to it.
        # No tags should be set in this case.
        initiators = self.host_obj.list_initiators(
            foundhostdetails['id'],
            self.configuration.coprhd_tenant)
        init_ports_uri_list = self.get_init_ports_uri_list(
            initiators, initiator_ports)
        exp_group_name = self._get_unique_exportgroup_name(connector)
        # First create an empty export group of type
        # Initiator
        self._create_export_group(exp_group_name,
                                  'Initiator')
        # Update the above export group with requested
        # Initiators
        self._update_export_group(exp_group_name,
                                  "initiator_changes",
                                  init_ports_uri_list)

        LOG.debug(
            "adding the volume to the exportgroup : %s",
            exp_group_name)
        self._add_volume_to_eg(exp_group_name, volumename)

        return

    def _handle_host_with_less_initiators(self, connector, foundhostdetails,
                                          protocol, volumename):
        """Updates host initiators having less initiators

        :param foundhostdetails: Details of the found host
        :param initiator_ports: Set of initiator ports
        :param volumename: Name of the volume
        """
        # Found a host having less than the requested
        # initiators. Update the host with the requested
        # initiator ports
        virt_inits_pair_wise = (
            self._get_formatted_virt_inits(
                connector['phy_to_virt_initiators']))
        # Add initiator pairs to host and set tags for them
        self.add_initiator_pairs_to_host(
            virt_inits_pair_wise, foundhostdetails['name'],
            protocol)
        # Now we create an export group of type Host and
        # add this updated host to it, the host initiators
        # will automatically be fetched.
        newexpgroupname = self._get_unique_exportgroup_name(foundhostdetails)
        self._create_export_group(newexpgroupname,
                                  'Host',
                                  foundhostdetails['name'])

        LOG.debug(
            "adding the volume to the exportgroup : %s",
            newexpgroupname)
        self._add_volume_to_eg(newexpgroupname, volumename)

        return

    def _handle_host_with_some_initiators(
            self,
            connector,
            foundhostdetails,
            protocol,
            initiator_ports,
            volumename):
        """Updates host with requested initiators

        :param connector: details of connector
        :param foundhostdetails: Details of the found host
        :param protocol: details of the protocol being used
        :param initiator_ports: Set of initiator ports
        :param volumename: Name of the volume
        """
        # Found host having some of its initiators same as
        # the requested initiators. Add all the requested
        # initiators to this host and create an Initiator
        # type export group with the requested initiators.
        virt_inits_pair_wise = (
            self._get_formatted_virt_inits(
                connector['phy_to_virt_initiators']))
        self.add_initiator_pairs_to_host(
            virt_inits_pair_wise, foundhostdetails['name'],
            protocol)
        initiators = self.host_obj.list_initiators(
            foundhostdetails['id'],
            self.configuration.coprhd_tenant)
        init_ports_uri_list = self.get_init_ports_uri_list(
            initiators, initiator_ports)

        exp_group_name = self._get_unique_exportgroup_name(connector)
        # First create an empty export group of type
        # Initiator
        self._create_export_group(exp_group_name,
                                  'Initiator')
        # Update the above export group with requested
        # Initiators
        self._update_export_group(exp_group_name,
                                  "initiator_changes",
                                  init_ports_uri_list)

        LOG.debug(
            "adding the volume to the exportgroup : %s",
            exp_group_name)
        self._add_volume_to_eg(exp_group_name, volumename)

        return

    def _create_host_and_eg(self, connector, protocol,
                            initiator_ports,
                            volumename):
        """Creates a host and export group.

        :param connector: details of connector
        :param protocol: details of the protocol being used
        :param initiator_ports: Set of initiator ports
        :param volumename: Name of the volume
        """
        # No host containing any of the requested initiator was
        # found. Therefore create a new host and add the requested
        # initiators to it
        LOG.debug(
            "No export group or host found. Creating new host and export group")
        try:
            self.host_obj.create(
                connector['host'],
                'AIX',
                connector['host'],
                self.configuration.coprhd_tenant,
                usessl=True,
                osversion=None,
                autodiscovery=False,
                bootvolume=None,
                project=None,
                testconnection=None,
                isVirtual=True
            )
            LOG.info(_("Created host %s") % connector['host'])
            # Set Openstack tags for the newly create host

            self.set_host_tags(connector)

        except coprhd_utils.CoprHdError:
            pass
        # Just add the requested initiators to it
        virt_inits_pair_wise = self._get_formatted_virt_inits(
            connector['phy_to_virt_initiators'])
        self.add_initiator_pairs_to_host(
            virt_inits_pair_wise, connector['host'], protocol)

        host_id = self.host_obj.query_by_name(connector['host'], 
                                              self.configuration.coprhd_tenant)
        initiators = self.host_obj.list_initiators(
            host_id,
            self.configuration.coprhd_tenant)

        # Now we create an export group of type Host and add this
        # host to it, the host initiators will automatically be
        # fetched create an export group for this host
        newexpgroupname = self._get_unique_exportgroup_name(connector)

        self._create_export_group(newexpgroupname,
                                  'Host',
                                  connector['host'])

        init_ports_uri_list = self.get_init_ports_uri_list(
            initiators, initiator_ports)

        self._update_export_group(newexpgroupname,
                                  "initiator_changes",
                                  init_ports_uri_list)
        LOG.debug(
            "adding the volume to the exportgroup : %s",
            newexpgroupname)
        self._add_volume_to_eg(newexpgroupname, volumename)

        return

    def _get_unique_exportgroup_name(self, resource):
        """Returns a unique export group name.

        :param resource: An object containing connector
        details or that of host.
        :returns A unique export group name.
        """

        try:
            exp_group_name = resource['host'] + 'SG'
        except KeyError:
            exp_group_name = resource['name'] + 'SG'

        # Create a unique name
        exp_group_name = exp_group_name + '-' + ''.join(
            random.choice(string.ascii_uppercase +
                          string.digits)
            for x in range(6))

        return exp_group_name

    def _check_associated_varray(self, groupdetails):
        """Checks for the varray associated with the Export Group.

        :param groupdetails: Contains details of the Export Group.
        :returns The details of the Export Group if they match the
        varray.
        """

        if groupdetails['varray']:
            varray_uri = groupdetails['varray']['id']
            varray_details = self.varray_obj.varray_show(
                varray_uri)

            if varray_details['name'] == (
                    self.configuration.coprhd_varray):
                return groupdetails

    def _add_volume_to_eg(self, export_group_name, volumename):
        """Adds a volume to an export group.

        :param exp_group_name: Name of the Export Group.
        :param volumename: Name of the volume.
        """

        self.exportgroup_obj.exportgroup_add_volumes(
            True, export_group_name,
            self.configuration.coprhd_tenant, None,
            None, None, self.configuration.coprhd_project,
            [volumename], None, None)

    def _update_export_group(self, export_group_name,
                             change_type, uri_list):
        """Updates an export group.

        :param export_group_name: Name of the Export Group.
        :param change_type: Initiator Changes or Host changes.
        :param uri_list: Contains URIs for initiators or Hosts.
        """

        self.exportgroup_obj.update(
            export_group_name,
            self.configuration.coprhd_project,
            self.configuration.coprhd_tenant,
            self.configuration.coprhd_varray,
            change_type, "add",
            uri_list)

    def _create_export_group(self, export_group_name,
                             export_group_type,
                             export_destination=None
                             ):
        """Creates an Export Group.

        :param export_group_name: Name of the Export Group
        :param export_group_type: Initiator or Host type Export Group
        :param export_destination: Whether export destination is a Host.
        """

        self.exportgroup_obj.exportgroup_create(
            export_group_name,
            self.configuration.coprhd_project,
            self.configuration.coprhd_tenant,
            self.configuration.coprhd_varray,
            export_group_type,
            export_destination)

    def _add_virtual_initiators_to_network(self, connector):
        """Adds virtual initiators of LPAR to the network.

        :param connector : Details of the connector
        """
        # Get a list of all formatted Physical initiators.
        physical_initiators = []
        for physical_initiator in connector['phy_to_virt_initiators'].keys():
            initiator = self._format_initiator(physical_initiator)
            physical_initiators.append(initiator)

        # Search for these physical initiators in all networks
        # present in CoprHD.
        for initiator in physical_initiators:
            network_uri = self._find_associated_network(initiator)
            # If a Physical initiator is found in the network,
            # its corresponding virtual initiators are added
            # to the network.
            if network_uri:
                virtual_initiators = []
                try:
                    initiators = connector['phy_to_virt_initiators'][initiator.replace(':','').lower()]                    
                except KeyError:
                    initiators = connector['phy_to_virt_initiators'][initiator.replace(':','')]
                                            
                for initiator in initiators:
                    virtual_initiators.append(initiator)

                formatted_virtual_initiators = []
                for virtual_initiator in virtual_initiators:
                    initiator = self._format_initiator(virtual_initiator)
                    formatted_virtual_initiators.append(initiator)

                for virtual_initiator in formatted_virtual_initiators:
                    self.network_obj.add_endpoint(network_uri,
                                                  virtual_initiator)
            else:
                raise coprhd_utils.CoprHdError(
                    coprhd_utils.CoprHdError.SOS_FAILURE_ERR,
                    _("The physical %(initiator)s: wasn't found in any,"
                      "network discovered in CoprHD\n") %
                     {'initiator': initiator})        
        return            
        

    def _find_associated_network(self, wwpn):
        """Finds the network associated to an initiator.

        :param wwpn: initiator port
        :returns URI of the network associated to the initiator
        """

        return self.network_obj.query_by_initiator(wwpn)

    def set_restricted_metadata(self, volume):
        """Sets the PowerVC restricted metadata properties.

        :param volume: Contains details of the volume.
        """

        # Now set the PowerVC restricted metadata.
        # We need to set this kind of restricted
        # meta-data otherwise volumes created from
        # PowerVC would also show up during Volume
        # on-board.

        self.authenticate_user()
        full_project_name = ("%s/%s" % (self.configuration.coprhd_tenant,
                                        self.configuration.coprhd_project))
        name = self._get_coprhd_volume_name(volume)
        vol_uri = self.volume_obj.volume_query(
            full_project_name, name)
        volume_details = self.volume_obj.show_by_uri(vol_uri)

        metadata = {'vdisk_id': volume_details['native_id'],
                    'vdisk_name': volume_details['device_label'],
                    'vdisk_uid': volume_details['wwn']
                    }

        LOG.debug("Set restricted metadata: %s" % metadata)

        ctxt = context.get_admin_context()
        powervc_db_api.\
            volume_restricted_metadata_update_or_create(ctxt, volume['id'],
                                                        metadata)
        return
    
    def _format_initiator(self, wwn):
        """Adds colons to the given initiator as needed for CoprHD.
        
        :param wwn : The wwn of the initiator.
        :returns The formatted initiator.
        """
        
        initiator = ':'.join(re.findall(
                        '..', wwn)).upper()
                        
        return initiator                
