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

import os
import random
import string
import sys
import time
import traceback

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg
try:
    from oslo.utils import excutils
except ImportError:
    try:
        from cinder.openstack.common import excutils
    except ImportError:
        from oslo_utils import excutils
try:
    from oslo_log import log as logging
except ImportError:
    from cinder.openstack.common import log as logging
try:
    from cinder.openstack.common.gettextutils import _
except ImportError:
    from cinder.i18n import _

from cinder import context
from cinder.volume.drivers.emc.coprhd.helpers \
    import authentication as CoprHD_auth
from cinder.volume.drivers.emc.coprhd.helpers \
    import consistencygroup as CoprHD_cg
from cinder.volume.drivers.emc.coprhd.helpers import exportgroup as CoprHD_eg
from cinder.volume.drivers.emc.coprhd.helpers import host as CoprHD_host
from cinder.volume.drivers.emc.coprhd.helpers import snapshot as CoprHD_snap
from cinder.volume.drivers.emc.coprhd.helpers import tag as CoprHD_tag
from cinder.volume.drivers.emc.coprhd.helpers \
    import commoncoprhdapi as CoprHD_utils
from cinder.volume.drivers.emc.coprhd.helpers \
    import virtualarray as CoprHD_varray
from cinder.volume.drivers.emc.coprhd.helpers import volume as CoprHD_vol
from cinder import exception
from cinder.volume import volume_types


LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.StrOpt('hostname',
               default=None,
               help='Hostname for the EMC CoprHD Instance'),
    cfg.IntOpt('coprhd_port',
               default=4443,
               help='Port for the EMC CoprHD Instance'),
    cfg.StrOpt('coprhd_username',
               default=None,
               help='Username for accessing the EMC CoprHD Instance'),
    cfg.StrOpt('coprhd_password',
               default=None,
               help='Password for accessing the EMC CoprHD Instance'),
    cfg.StrOpt('coprhd_tenant',
               default=None,
               help='Tenant to utilize within the EMC CoprHD Instance'),
    cfg.StrOpt('coprhd_project',
               default=None,
               help='Project to utilize within the EMC CoprHD Instance'),
    cfg.StrOpt('coprhd_varray',
               default=None,
               help='Virtual Array to utilize within the EMC CoprHD Instance'),
    cfg.StrOpt('coprhd_scaleio_rest_gateway_ip',
               default='None',
               help='Rest Gateway for Scaleio'),
    cfg.StrOpt('coprhd_scaleio_rest_gateway_port',
               default='None',
               help='Rest Gateway Port for Scaleio'),
    cfg.StrOpt('coprhd_scaleio_rest_server_username',
               default=None,
               help='Username for Rest Gateway'),
    cfg.StrOpt('coprhd_scaleio_rest_server_password',
               default=None,
               help='Rest Gateway Password'),
    cfg.StrOpt('scaleio_verify_server_certificate',
               default='False',
               help='verify server certificate'),
    cfg.StrOpt('scaleio_server_certificate_path',
               default=None,
               help='Server certificate path'),
    cfg.StrOpt('coprhd_emulate_snapshot',
               default='False',
               help='True | False to indicate if the storage array' +
               'in CoprHD is VMAX or VPLEX'),
    cfg.StrOpt('coprhd_security_file',
               default=None,
               help='Path of security file')
]

CONF = cfg.CONF
CONF.register_opts(volume_opts)

URI_VPOOL_VARRAY_CAPACITY = '/block/vpools/{0}/varrays/{1}/capacity'
URI_BLOCK_EXPORTS_FOR_INITIATORS = '/block/exports?initiators={0}'
EXPORT_RETRY_COUNT = 5


def retry_wrapper(func):
    def try_and_retry(*args, **kwargs):
        retry = False

        try:
            return func(*args, **kwargs)
        except CoprHD_utils.CoprHdError as e:
            # if we got an http error and
            # the string contains 401 or if the string contains the word cookie
            if (e.err_code == CoprHD_utils.CoprHdError.HTTP_ERR and
                (e.err_text.find('401') != -1 or
                 e.err_text.lower().find('cookie') != -1)):
                retry = True
                EMCCoprHDDriverCommon.AUTHENTICATED = False
            else:
                exception_message = "\nCoprHD Exception: %s\nStack Trace:\n%s" \
                    % (e.err_text, traceback.format_exc())
                raise exception.VolumeBackendAPIException(
                    data=exception_message)
        except Exception:
            exception_message = "\nGeneral Exception: %s\nStack Trace:\n%s" \
                % (sys.exc_info()[0], traceback.format_exc())
            raise exception.VolumeBackendAPIException(
                data=exception_message)

        if retry:
            return func(*args, **kwargs)

    return try_and_retry


class EMCCoprHDDriverCommon(object):

    OPENSTACK_TAG = 'OpenStack'
    AUTHENTICATED = False

    def __init__(self, protocol, default_backend_name, configuration=None):
        self.protocol = protocol
        self.configuration = configuration
        self.configuration.append_config_values(volume_opts)

        self.init_coprhd_api_components()

        self.stats = {'driver_version': '1.0',
                      'free_capacity_gb': 'unknown',
                      'reserved_percentage': '0',
                      'storage_protocol': protocol,
                      'total_capacity_gb': 'unknown',
                      'vendor_name': 'EMC',
                      'volume_backend_name':
                      self.configuration.volume_backend_name or
                      default_backend_name}

    def init_coprhd_api_components(self):

        CoprHD_utils.COOKIE = None

        # instantiate a few coprhd api objects for later use
        self.volume_obj = CoprHD_vol.Volume(
            self.configuration.hostname,
            self.configuration.coprhd_port)

        self.exportgroup_obj = CoprHD_eg.ExportGroup(
            self.configuration.hostname,
            self.configuration.coprhd_port)

        self.host_obj = CoprHD_host.Host(
            self.configuration.hostname,
            self.configuration.coprhd_port)

        self.varray_obj = CoprHD_varray.VirtualArray(
            self.configuration.hostname,
            self.configuration.coprhd_port)

        self.snapshot_obj = CoprHD_snap.Snapshot(
            self.configuration.hostname,
            self.configuration.coprhd_port)

        self.consistencygroup_obj = CoprHD_cg.ConsistencyGroup(
            self.configuration.hostname,
            self.configuration.coprhd_port)

    def check_for_setup_error(self):
        # validate all of the coprhd_* configuration values
        if self.configuration.hostname is None:
            message = "hostname is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_port is None:
            message = "coprhd_port is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_username is None:
            message = "coprhd_username is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_password is None:
            message = "coprhd_password is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_tenant is None:
            message = "coprhd_tenant is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_project is None:
            message = "coprhd_project is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

        if self.configuration.coprhd_varray is None:
            message = "coprhd_varray is not set in cinder configuration"
            raise exception.VolumeBackendAPIException(data=message)

    def authenticate_user(self):
        # we should check to see if we are already authenticated before blindly
        # doing it again
        if EMCCoprHDDriverCommon.AUTHENTICATED is False:
            obj = CoprHD_auth.Authentication(
                self.configuration.hostname,
                self.configuration.coprhd_port)

            username = None
            password = None

            if((self.configuration.coprhd_security_file is not '') and
                    (self.configuration.coprhd_security_file is not None)):
                from Crypto.Cipher import ARC4
                import getpass
                obj1 = ARC4.new(getpass.getuser())
                security_file = open(
                    self.configuration.coprhd_security_file, 'r')
                cipher_text = security_file.readline().rstrip()
                username = obj1.decrypt(cipher_text)
                cipher_text = security_file.readline().rstrip()
                password = obj1.decrypt(cipher_text)
                security_file.close()
            else:
                username = self.configuration.coprhd_username
                password = self.configuration.coprhd_password

            CoprHD_utils.AUTH_TOKEN = obj.authenticate_user(username,
                                                            password)

            EMCCoprHDDriverCommon.AUTHENTICATED = True

    @retry_wrapper
    def create_volume(self, vol, driver):
        self.authenticate_user()
        name = self._get_volume_name(vol)
        size = int(vol['size']) * 1073741824

        vpool = self._get_vpool(vol)
        self.vpool = vpool['CoprHD:VPOOL']

        try:
            cgid = None
            try:
                cgid = vol['consistencygroup_id']
                ctx = context.get_admin_context()
                if(cgid):
                    CoprHD_cgid = self._get_coprhd_cgid(driver, ctx, cgid)
            except AttributeError as e:
                CoprHD_cgid = None

            self.volume_obj.create(
                self.configuration.coprhd_tenant + "/" +
                self.configuration.coprhd_project,
                name, size, self.configuration.coprhd_varray,
                self.vpool,
                # no longer specified in volume creation
                sync=True,
                # no longer specified in volume creation
                consistencygroup=CoprHD_cgid)
        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Volume " + name + ": create failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Volume : %s creation failed") % name)

    @retry_wrapper
    def create_consistencygroup(self, context, group):
        self.authenticate_user()
        name = group['name']

        try:
            self.consistencygroup_obj.create(
                name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            cgUri = self.consistencygroup_obj.consistencygroup_query(
                name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            self.set_tags_for_resource(
                CoprHD_cg.ConsistencyGroup.URI_CONSISTENCY_GROUP_TAGS,
                cgUri, group)

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Consistency Group " + name + ": create failed\n" +
                    e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Consistency Group : %s creation failed") % name)

    @retry_wrapper
    def update_consistencygroup(self, driver, context, group, add_volumes,
                                remove_volumes):
        self.authenticate_user()
        model_update = {'status': 'available'}
        cg_uri = self._get_coprhd_consistency_group_id(group)
        add_volnames = []
        remove_volnames = []

        try:
            if(add_volumes):
                for vol in add_volumes:
                    vol_name = self._get_coprhd_volume_name(vol)
                    add_volnames.append(vol_name)

            if(remove_volumes):
                for vol in remove_volumes:
                    vol_name = self._get_coprhd_volume_name(vol)
                    remove_volnames.append(vol_name)

            self.consistencygroup_obj.update(
                cg_uri,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant,
                add_volnames, remove_volnames, True)

            return model_update, None, None

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Consistency Group " + cg_uri + ": update failed\n" +
                    e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Consistency Group : %s update failed") % cg_uri)

    def _get_coprhd_consistency_group_id(self, cg, verbose=False):
        tagname = "OpenStack:id:" + cg['id']
        rslt = CoprHD_utils.search_by_tag(
            CoprHD_cg.ConsistencyGroup.URI_SEARCH_CONSISTENCY_GROUPS_BY_TAG.
            format(tagname),
            self.configuration.hostname,
            self.configuration.coprhd_port)

        if(len(rslt) > 0):
            rsltCg = self.consistencygroup_obj.show(
                rslt[0],
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            if(verbose is True):
                return rsltCg['id'], rslt[0]
            else:
                return rsltCg['id']
        else:
            raise CoprHD_utils.CoprHdError(
                CoprHD_utils.CoprHdError.NOT_FOUND_ERR,
                "Consistency Group " + cg['id'] + " not found")

    @retry_wrapper
    def delete_consistencygroup(self, driver, context, group):
        self.authenticate_user()
        name = group['name']

        try:
            volumes = driver.db.volume_get_all_by_group(
                context, group['id'])

            for vol in volumes:
                vol_name = self._get_coprhd_volume_name(vol)

                self.volume_obj.delete(
                    self.configuration.coprhd_tenant +
                    "/" +
                    self.configuration.coprhd_project +
                    "/" +
                    vol_name,
                    sync=True,
                    forceDelete=True)

                vol['status'] = 'deleted'

            self.consistencygroup_obj.delete(
                name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            model_update = {}
            model_update['status'] = group['status']

            return model_update, volumes

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Consistency Group " + name + ": delete failed\n" +
                    e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Consistency Group : %s deletion failed") % name)

    @retry_wrapper
    def create_cgsnapshot(self, driver, context, cgsnapshot):
        self.authenticate_user()

        cgsnapshot_id = cgsnapshot['id']
        cgsnapshot_name = cgsnapshot['name']
        cg_id = cgsnapshot['consistencygroup_id']
        cg_name = None

        if(cg_id):
            CoprHD_cgid = self._get_coprhd_cgid(driver, context, cg_id)
            cg_name = self._get_consistencygroup_name(driver, context, cg_id)

        snapshots = driver.db.snapshot_get_all_for_cgsnapshot(
            context, cgsnapshot_id)

        model_update = {}
        LOG.info(_('Start to create cgsnapshot for consistency group'
                   ': %(group_name)s') %
                 {'group_name': cg_name})

        try:
            self.snapshot_obj.snapshot_create(
                'block',
                'consistency-groups',
                CoprHD_cgid,
                cgsnapshot_name,
                False,
                True)

            for snapshot in snapshots:
                vol_id_of_snap = snapshot['volume_id']

                '''Finding the volume in CoprHD for this volume id'''
                tagname = "OpenStack:id:" + vol_id_of_snap
                rslt = CoprHD_utils.search_by_tag(
                    CoprHD_vol.Volume.URI_SEARCH_VOLUMES_BY_TAG.format(
                        tagname),
                    self.configuration.hostname,
                    self.configuration.coprhd_port)

                if((rslt is None) or (len(rslt) == 0)):
                    continue

                volUri = rslt[0]

                snapshots_of_volume = self.snapshot_obj.snapshot_list_uri(
                    'block',
                    'volumes',
                    volUri)

                for snapUri in snapshots_of_volume:
                    snapshot_obj = self.snapshot_obj.snapshot_show_uri(
                        'block',
                        volUri,
                        snapUri['id'])

                    if(False == (CoprHD_utils.get_node_value(snapshot_obj,
                                                             'inactive'))):

                        '''When we create a consistency group snapshot on
                           coprhd then each snapshot of volume in the
                           consistencygroup will be given a subscript. Ex if
                           the snapshot name is cgsnap1 and lets say there are
                           three vols(a,b,c) in CG. Then the names of snapshots
                           of the volumes in cg on coprhd end will be like
                           cgsnap1-1 cgsnap1-2 cgsnap1-3. So, we list the
                           snapshots of the volume under consideration and then
                           split the name  using - from the ending as prefix
                           and postfix. We compare the prefix to the cgsnapshot
                           name and filter our the snapshots that correspond to
                           the cgsnapshot
                        '''
                        if('-' in snapshot_obj['name']):
                            (prefix, postfix) = snapshot_obj[
                                'name'].rsplit('-', 1)

                            if(cgsnapshot_name == prefix):
                                self.set_tags_for_resource(
                                    CoprHD_snap.Snapshot.
                                    URI_BLOCK_SNAPSHOTS_TAG,
                                    snapUri['id'],
                                    snapshot)

                        elif(cgsnapshot_name == snapshot_obj['name']):
                            self.set_tags_for_resource(
                                CoprHD_snap.Snapshot.URI_BLOCK_SNAPSHOTS_TAG,
                                snapUri['id'],
                                snapshot)

                snapshot['status'] = 'available'

            model_update['status'] = 'available'

            return model_update, snapshots

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot for Consistency Group " + cg_name +
                    ": create failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Snapshot %(name)s for Consistency Group" +
                                    " : %(cg_name)s creation failed")
                                  % {'cg_name': cg_name,
                                     'name': cgsnapshot_name})

    @retry_wrapper
    def delete_cgsnapshot(self, driver, context, cgsnapshot):
        self.authenticate_user()
        cgsnapshot_id = cgsnapshot['id']
        cgsnapshot_name = cgsnapshot['name']

        cg_id = cgsnapshot['consistencygroup_id']

        CoprHD_cgid = self._get_coprhd_cgid(driver, context, cg_id)
        cg_name = self._get_consistencygroup_name(driver, context, cg_id)
        snapshots = driver.db.snapshot_get_all_for_cgsnapshot(
            context, cgsnapshot_id)

        model_update = {}
        model_update['status'] = cgsnapshot['status']
        LOG.info(_('Delete cgsnapshot %(snap_name)s for consistency group: '
                   '%(group_name)s') % {'snap_name': cgsnapshot['name'],
                                        'group_name': cg_name})

        try:
            uri = None
            try:
                uri = self.snapshot_obj.snapshot_query('block',
                                                       'consistency-groups',
                                                       CoprHD_cgid,
                                                       cgsnapshot_name + '-1')
            except CoprHD_utils.CoprHdError as e:
                if e.err_code == CoprHD_utils.CoprHdError.NOT_FOUND_ERR:
                    uri = self.snapshot_obj.snapshot_query(
                        'block',
                        'consistency-groups',
                        CoprHD_cgid,
                        cgsnapshot_name)
            self.snapshot_obj.snapshot_delete_uri(
                'block',
                CoprHD_cgid,
                uri,
                True)

            for snapshot in snapshots:
                snapshot['status'] = 'deleted'

            return model_update, snapshots

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot " + cgsnapshot_id + " for Consistency Group " +
                    cg_name +
                    ": delete failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Snapshot %(name)s for Consistency Group" +
                                    ": %(cg_name)s deletion failed")
                                  % {'cg_name': cg_name,
                                      'name': cgsnapshot_name})

    @retry_wrapper
    def set_volume_tags(self, vol, exemptTags=[]):
        self.authenticate_user()
        name = self._get_volume_name(vol)

        vol_uri = self.volume_obj.volume_query(
            self.configuration.coprhd_tenant +
            "/" +
            self.configuration.coprhd_project +
            "/" + name)

        self.set_tags_for_resource(
            CoprHD_vol.Volume.URI_TAG_VOLUME, vol_uri, vol, exemptTags)

    @retry_wrapper
    def set_tags_for_resource(self, uri, resourceId, resource, exemptTags=[]):

        self.authenticate_user()

        # first, get the current tags that start with the OPENSTACK_TAG
        # eyecatcher
        formattedUri = uri.format(resourceId)
        remove_tags = []
        currentTags = CoprHD_tag.list_tags(self.configuration.hostname,
                                           self.configuration.coprhd_port,
                                           formattedUri)
        for cTag in currentTags:
            if cTag.startswith(self.OPENSTACK_TAG):
                remove_tags.append(cTag)

        try:
            if len(remove_tags) > 0:
                CoprHD_tag.tag_resource(
                    self.configuration.hostname,
                    self.configuration.coprhd_port,
                    uri,
                    resourceId,
                    None,
                    remove_tags)
        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                LOG.debug("CoprHdError adding the tag: " + e.err_text)

        # now add the tags for the resource
        add_tags = []
        # put all the openstack resource properties into the CoprHD resource

        try:
            for prop, value in vars(resource).iteritems():
                try:
                    if(prop in exemptTags):
                        continue

                    if(prop.startswith("_")):
                        prop = prop.replace("_", '', 1)

                    # don't put the status in, it's always the status before
                    # the current transaction
                    if ((not prop.startswith("status") and not
                         prop.startswith("obj_status") and
                         prop != "obj_volume") and (value)):
                        add_tags.append(
                            self.OPENSTACK_TAG +
                            ":" +
                            prop +
                            ":" +
                            str(value))
                except TypeError:
                    LOG.debug("Error tagging the resource property %s ", prop)
        except TypeError:
            LOG.debug("Error tagging the resource properties ")

        try:
            CoprHD_tag.tag_resource(
                self.configuration.hostname,
                self.configuration.coprhd_port,
                uri,
                resourceId,
                add_tags,
                None)
        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                LOG.debug("CoprHdError adding the tag: " + e.err_text)

        return CoprHD_tag.list_tags(self.configuration.hostname,
                                    self.configuration.coprhd_port,
                                    formattedUri)

    @retry_wrapper
    def create_cloned_volume(self, vol, src_vref):
        """Creates a clone of the specified volume."""
        self.authenticate_user()
        name = self._get_volume_name(vol)
        srcname = self._get_coprhd_volume_name(src_vref)

        try:
            if(src_vref['consistencygroup_id']):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Clone can't be taken individually on a volume" +
                    " that is part of a Consistency Group")
        except AttributeError as e:
            LOG.info("No Consistency Group associated with the volume")

        try:
            (storageresType, storageresTypename) = \
                self.volume_obj.get_storageAttributes(
                srcname, None, None)

            resource_id = self.volume_obj.storageResource_query(
                storageresType,
                srcname,
                None,
                None,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            self.volume_obj.clone(
                name,
                resource_id,
                sync=True)

            clone_vol_path = self.configuration.coprhd_tenant + \
                "/" + self.configuration.coprhd_project + "/" + name
            detachable = self.volume_obj.is_volume_detachable(clone_vol_path)
            LOG.info("Is volume detachable : " + str(detachable))

            # detach it from the source volume immediately after creation
            if(detachable):
                self.volume_obj.volume_clone_detach("", clone_vol_path, True)

        except IndexError as e:
            LOG.exception("Volume clone detach returned empty task list")

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Volume " + name + ": clone failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Volume : {%s} clone failed") % name)

    @retry_wrapper
    def expand_volume(self, vol, new_size):
        """expands the volume to new_size specified."""
        self.authenticate_user()
        volume_name = self._get_coprhd_volume_name(vol)
        size_in_bytes = CoprHD_utils.to_bytes(str(new_size) + "G")

        try:
            self.volume_obj.expand(
                self.configuration.coprhd_tenant +
                "/" +
                self.configuration.coprhd_project +
                "/" +
                volume_name,
                size_in_bytes,
                True)
        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Volume " + volume_name + ": expand failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Volume : %s expand failed") % volume_name)

    @retry_wrapper
    def create_volume_from_snapshot(self, snapshot, volume, volume_db):
        """Creates volume from given snapshot ( snapshot clone to volume )."""
        self.authenticate_user()

        if self.configuration.coprhd_emulate_snapshot == 'True':
            self.create_cloned_volume(volume, snapshot)
            return

        ctxt = context.get_admin_context()

        src_snapshot_name = None

        # src_snapshot_name = snapshot['display_name']
        src_vol_ref = volume_db.volume_get(ctxt, snapshot['volume_id'])
        new_volume_name = self._get_volume_name(volume)

        try:
            src_vol_name, src_vol_uri = self._get_coprhd_volume_name(
                src_vol_ref, True)
            src_snapshot_name = self._get_CoprHD_snapshot_name(
                snapshot, src_vol_uri)

            (storageresType, storageresTypename) = \
                self.volume_obj.get_storageAttributes(
                src_vol_name, None, src_snapshot_name)

            resource_id = self.volume_obj.storageResource_query(
                storageresType,
                src_vol_name,
                None,
                src_snapshot_name,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)

            self.volume_obj.clone(
                new_volume_name,
                resource_id,
                sync=True)

        except CoprHD_utils.CoprHdError as e:
            if(e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot " +
                    src_snapshot_name +
                    ": clone failed\n" +
                    e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Snapshot : %s clone failed") % src_snapshot_name)

    @retry_wrapper
    def delete_volume(self, vol):
        self.authenticate_user()
        name = self._get_coprhd_volume_name(vol)
        try:
            self.volume_obj.delete(
                self.configuration.coprhd_tenant +
                "/" +
                self.configuration.coprhd_project +
                "/" +
                name,
                sync=True)
        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.NOT_FOUND_ERR:
                LOG.info(_(
                    "Volume %s"
                    " no longer exists; volume deletion is"
                    " considered success.") % name)
            elif e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Volume " + name + ": Delete failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Volume : %s delete failed") % name)

    @retry_wrapper
    def list_volume(self):
        try:
            uris = self.volume_obj.list_volumes(
                self.configuration.coprhd_tenant +
                "/" +
                self.configuration.coprhd_project)
            if len(uris) > 0:
                output = []
                for uri in uris:
                    output.append(self.volume_obj.show_by_uri(uri))

                return CoprHD_utils.format_json_object(output)
            else:
                return
        except CoprHD_utils.CoprHdError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("List volumes failed"))

    @retry_wrapper
    def create_snapshot(self, snapshot, volume_db):
        self.authenticate_user()

        ctxt = context.get_admin_context()
        volume_id = snapshot['volume_id']
        volume = volume_db.volume_get(ctxt, volume_id)

        try:
            if(volume['consistencygroup_id']):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot can't be taken individually on a volume" +
                    " that is part of a Consistency Group")
        except AttributeError as e:
            LOG.info("No Consistency Group associated with the volume")

        if self.configuration.coprhd_emulate_snapshot == 'True':
            self.create_cloned_volume(snapshot, volume)
            self.set_volume_tags(snapshot, ['_volume', '_obj_volume_type'])
            return

        try:
            snapshotname = self._get_snapshot_name(snapshot)
            vol = snapshot['volume']

            volumename = self._get_coprhd_volume_name(vol)
            projectname = self.configuration.coprhd_project
            tenantname = self.configuration.coprhd_tenant
            storageresType = 'block'
            storageresTypename = 'volumes'
            resourceUri = self.snapshot_obj.storageResource_query(
                storageresType,
                volumeName=volumename,
                cgName=None,
                project=projectname,
                tenant=tenantname)
            inactive = False
            sync = True
            self.snapshot_obj.snapshot_create(
                storageresType,
                storageresTypename,
                resourceUri,
                snapshotname,
                inactive,
                sync)

            snapshotUri = self.snapshot_obj.snapshot_query(
                storageresType,
                storageresTypename,
                resourceUri,
                snapshotname)

            self.set_tags_for_resource(
                CoprHD_snap.Snapshot.URI_BLOCK_SNAPSHOTS_TAG,
                snapshotUri, snapshot, ['_volume'])

        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot: " +
                    snapshotname +
                    ", Create Failed\n" +
                    e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Snapshot : %s create failed") % snapshotname)

    @retry_wrapper
    def delete_snapshot(self, snapshot):
        self.authenticate_user()

        vol = snapshot['volume']

        try:
            if(vol['consistencygroup_id']):
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot delete can't be done individually on a volume" +
                    " that is part of a Consistency Group")
        except AttributeError as e:
            LOG.info("No Consistency Group associated with the volume")

        if self.configuration.coprhd_emulate_snapshot == 'True':
            self.delete_volume(snapshot)
            return

        snapshotname = None
        try:
            volumename = self._get_coprhd_volume_name(vol)
            projectname = self.configuration.coprhd_project
            tenantname = self.configuration.coprhd_tenant
            storageresType = 'block'
            storageresTypename = 'volumes'
            resourceUri = self.snapshot_obj.storageResource_query(
                storageresType,
                volumeName=volumename,
                cgName=None,
                project=projectname,
                tenant=tenantname)
            if resourceUri is None:
                LOG.info(_(
                    "Snapshot %s"
                    " is not found; snapshot deletion"
                    " is considered successful.") % snapshotname)
            else:
                snapshotname = self._get_CoprHD_snapshot_name(
                    snapshot, resourceUri)

                self.snapshot_obj.snapshot_delete(
                    storageresType,
                    storageresTypename,
                    resourceUri,
                    snapshotname,
                    sync=True)
        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Snapshot " +
                    snapshotname +
                    ": Delete Failed\n")
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Snapshot : %s delete failed") % snapshotname)

    @retry_wrapper
    def initialize_connection(self,
                              volume,
                              protocol,
                              initiatorNodes,
                              initiatorPorts,
                              hostname):

        try:
            self.authenticate_user()
            volumename = self._get_coprhd_volume_name(volume)
            foundgroupname = self._find_exportgroup(initiatorPorts)
            foundhostname = None
            if foundgroupname is None:
                for i in xrange(len(initiatorPorts)):
                    # check if this initiator is contained in any CoprHD Host
                    # object
                    LOG.debug(
                        "checking for initiator port:" + initiatorPorts[i])
                    foundhostname = self._find_host(initiatorPorts[i])
                    if ((foundhostname is None) and
                            (i + 1 == len(initiatorPorts))):
                        LOG.error("Auto host creation not supported")
                    else:
                        LOG.info(_("Found host %s") % foundhostname)
                # create an export group for this host
                foundgroupname = foundhostname + 'SG'
                # create a unique name
                foundgroupname = foundgroupname + '-' + \
                    ''.join(random.choice(string.ascii_uppercase +
                                          string.digits)
                            for x in range(6))
                self.exportgroup_obj.exportgroup_create(
                    foundgroupname,
                    self.configuration.coprhd_project,
                    self.configuration.coprhd_tenant,
                    self.configuration.coprhd_varray,
                    'Host',
                    foundhostname)

            next_lun_id = 1
            for try_id in range(1, EXPORT_RETRY_COUNT + 1):
                try:
                    coprhd_exportgroup = self.exportgroup_obj.exportgroup_show(
                        foundgroupname,
                        self.configuration.coprhd_project,
                        self.configuration.coprhd_tenant,
                        None, False)

                except CoprHD_utils.CoprHdError as e:
                    if e.err_code == CoprHD_utils.CoprHdError.NOT_FOUND_ERR:
                        self.exportgroup_obj.exportgroup_create(
                            foundgroupname,
                            self.configuration.coprhd_project,
                            self.configuration.coprhd_tenant,
                            self.configuration.coprhd_varray,
                            'Host',
                            foundhostname)

                # We explicitly give lun id an unused value greater then 0.
                # This is to get around the problem, which crops up while
                # creating volume from image when cinder node is different
                # from nova node.
                # When using lun id of 0, export of volume is having problems.
                volumes_list = [vol['lun']
                                for vol in coprhd_exportgroup['volumes']]
                volumes_list.sort()
                for iter_var in volumes_list:
                    if(iter_var > next_lun_id):
                        break
                    elif(iter_var < next_lun_id):
                        continue
                    elif(iter_var == next_lun_id):
                        next_lun_id = next_lun_id + 1

                LOG.debug(
                    "adding the volume to the exportgroup : " + volumename)
                try:
                    self.exportgroup_obj.exportgroup_add_volumes(
                        True,
                        foundgroupname,
                        self.configuration.coprhd_tenant,
                        None,
                        None,
                        None,
                        self.configuration.coprhd_project,
                        [volumename + ":" + str(next_lun_id)],
                        None,
                        None)
                    break
                except CoprHD_utils.CoprHdError as ex:
                    if (try_id >= EXPORT_RETRY_COUNT):
                        raise CoprHD_utils.CoprHdError(
                            CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                            "Attach volume (" +
                            self._get_coprhd_volume_name(volume) +
                            ") to host (" +
                            hostname +
                            ") initiator (" +
                            initiatorPorts[0] +
                            ") failed: " +
                            ex.err_text)
                    else:
                        LOG.exception(_("Export volume with LUN: %s failed.")
                                      % str(next_lun_id))
                        LOG.info("Retry with next available LUN ID")
                        next_lun_id = next_lun_id + 1

            return self._find_device_info(volume, initiatorPorts)

        except CoprHD_utils.CoprHdError as e:
            raise CoprHD_utils.CoprHdError(
                CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                "Attach volume (" +
                self._get_coprhd_volume_name(
                    volume) +
                ") to host (" +
                hostname +
                ") initiator (" +
                initiatorPorts[
                    0] +
                ") failed: " +
                e.err_text)

    @retry_wrapper
    def terminate_connection(self,
                             volume,
                             protocol,
                             initiatorNodes,
                             initiatorPorts,
                             hostname):
        try:
            self.authenticate_user()
            volumename = self._get_coprhd_volume_name(volume)
            tenantproject = self.configuration.coprhd_tenant + \
                '/' + self.configuration.coprhd_project
            voldetails = self.volume_obj.show(tenantproject + '/' + volumename)
            volid = voldetails['id']

            # find the exportgroups
            exports = self.volume_obj.get_exports_by_uri(volid)
            exportgroups = set()
            itls = exports['itl']
            for itl in itls:
                itl_port = itl['initiator']['port']
                if itl_port in initiatorPorts:
                    exportgroups.add(itl['export']['id'])

            for exportgroup in exportgroups:
                self.exportgroup_obj.exportgroup_remove_volumes_by_uri(
                    exportgroup,
                    volid,
                    True,
                    None,
                    None,
                    None,
                    None)
            else:
                LOG.info(_(
                    "No export group found for the host: %s"
                    "; this is considered already detached.") % hostname)

            return itls

        except CoprHD_utils.CoprHdError as e:
            raise CoprHD_utils.CoprHdError(
                CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                "Detaching volume " +
                volumename +
                " from host " +
                hostname +
                " failed: " +
                e.err_text)

    @retry_wrapper
    def _find_device_info(self, volume, initiator_ports):
        '''Returns the device_info in a list of itls that have
        the matched initiator
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
        '''
        volumename = self._get_coprhd_volume_name(volume)
        fullname = self.configuration.coprhd_project + '/' + volumename
        vol_uri = self.volume_obj.volume_query(fullname)

        '''
        The itl info shall be available at the first try since now export is a
        synchronous call.  We are trying a few more times to accommodate any
        delay on filling in the itl info after the export task is completed.
        '''
        itls = []
        for x in xrange(10):
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
                        LOG.debug("Found Device Number: " +
                                  str(found_device_number))
                        itls.append(itl)

            if itls:
                break
            else:
                LOG.debug("Device Number not found yet." +
                          " Retrying after 10 seconds...")
                time.sleep(10)

        if itls is None:
            # No device number found after 10 tries; return an empty itl
            LOG.info(_(
                "No device number has been found after 10 tries;"
                "this likely indicates an unsuccessful attach of"
                "volume volumename=%(volumename)s to"
                " initiator  initiator_ports=%(initiator_ports)s") %
                {'volumename': volumename,
                    'initiator_ports': str(initiator_ports)})

        return itls

    def _get_coprhd_cgid(self, driver, context, cgid):
        consisgrp = driver.db.consistencygroup_get(context, cgid)
        cgid = consisgrp['id']
        return cgid

    def _get_consistencygroup_name(self, driver, context, cgid):
        consisgrp = driver.db.consistencygroup_get(context, cgid)
        cgname = consisgrp['name']
        return cgname

    def _get_CoprHD_snapshot_name(self, snapshot, resUri):
        tagname = "OpenStack:id:" + snapshot['id']
        rslt = CoprHD_utils.search_by_tag(
            CoprHD_snap.Snapshot.URI_SEARCH_SNAPSHOT_BY_TAG.format(tagname),
            self.configuration.hostname,
            self.configuration.coprhd_port)

        # if the result is empty, then search with the tagname
        # as "OpenStack:obj_id"
        # as snapshots will be having the obj_id instead of just id.
        if((rslt is None) or (len(rslt) == 0)):
            tagname = "OpenStack:obj_id:" + snapshot['id']
            rslt = CoprHD_utils.search_by_tag(
                CoprHD_snap.Snapshot.URI_SEARCH_SNAPSHOT_BY_TAG.format(
                    tagname),
                self.configuration.hostname,
                self.configuration.coprhd_port)

        if((rslt is None) or (len(rslt) == 0)):
            return snapshot['name']
        else:
            rsltSnap = self.snapshot_obj.snapshot_show_uri(
                'block',
                resUri,
                rslt[0])
            return rsltSnap['name']

    def _get_coprhd_volume_name(self, vol, verbose=False):
        tagname = "OpenStack:id:" + vol['id']
        rslt = CoprHD_utils.search_by_tag(
            CoprHD_vol.Volume.URI_SEARCH_VOLUMES_BY_TAG.format(tagname),
            self.configuration.hostname,
            self.configuration.coprhd_port)

        # if the result is empty, then search with the tagname
        # as "OpenStack:obj_id"
        # as snapshots will be having the obj_id instead of just id.
        if(len(rslt) == 0):
            tagname = "OpenStack:obj_id:" + vol['id']
            rslt = CoprHD_utils.search_by_tag(
                CoprHD_vol.Volume.URI_SEARCH_VOLUMES_BY_TAG.format(tagname),
                self.configuration.hostname,
                self.configuration.coprhd_port)

        if(len(rslt) > 0):
            rsltVol = self.volume_obj.show_by_uri(rslt[0])

            if(verbose is True):
                return rsltVol['name'], rslt[0]
            else:
                return rsltVol['name']
        else:
            raise CoprHD_utils.CoprHdError(
                CoprHD_utils.CoprHdError.NOT_FOUND_ERR,
                "Volume " + vol['display_name'] + " not found")

    def _get_volume_name(self, vol):

        name = vol.get('display_name', None)

        if name is None or len(name) == 0:
            name = vol['name']

        return name

    def _get_snapshot_name(self, snap):

        name = snap.get('display_name', None)

        if name is None or len(name) == 0:
            name = snap['name']

        return name

    def _get_vpool(self, volume):
        vpool = {}
        ctxt = context.get_admin_context()
        type_id = volume['volume_type_id']
        if type_id is not None:
            volume_type = volume_types.get_volume_type(ctxt, type_id)
            specs = volume_type.get('extra_specs')
            for key, value in specs.iteritems():
                vpool[key] = value

        return vpool

    @retry_wrapper
    def _find_exportgroup(self, initiator_ports):
        """Find the export group to which the given initiator ports are the
        same as the initiators in the group
        """
        foundgroupname = None
        grouplist = self.exportgroup_obj.exportgroup_list(
            self.configuration.coprhd_project,
            self.configuration.coprhd_tenant)
        for groupid in grouplist:
            groupdetails = self.exportgroup_obj.exportgroup_show(
                groupid,
                self.configuration.coprhd_project,
                self.configuration.coprhd_tenant)
            if groupdetails is not None:
                if groupdetails['inactive']:
                    continue
                initiators = groupdetails['initiators']
                if initiators is not None:
                    inits_eg = set()
                    for initiator in initiators:
                        inits_eg.add(initiator['initiator_port'])

                    if inits_eg <= set(initiator_ports):
                        foundgroupname = groupdetails['name']
                    if foundgroupname is not None:
                        # Check the associated varray
                        if groupdetails['varray']:
                            varray_uri = groupdetails['varray']['id']
                            varray_details = self.varray_obj.varray_show(
                                varray_uri)
                            if varray_details['name'] == \
                                    self.configuration.coprhd_varray:
                                LOG.debug(
                                    "Found exportgroup " +
                                    foundgroupname)
                                break

                        # Not the right varray
                        foundgroupname = None

        return foundgroupname

    @retry_wrapper
    def _find_host(self, initiator_port):
        '''Find the host, if exists, to which the given initiator belong.'''
        foundhostname = None
        hosts = self.host_obj.list_all(self.configuration.coprhd_tenant)
        for host in hosts:
            initiators = self.host_obj.list_initiators(host['id'])
            for initiator in initiators:
                if initiator_port == initiator['name']:
                    foundhostname = host['name']
                    break

            if foundhostname is not None:
                break

        return foundhostname

    @retry_wrapper
    def _host_exists(self, host_name):
        """Check if a Host object with the given
        hostname already exists in CoprHD
        """
        hosts = self.host_obj.search_by_name(host_name)

        if len(hosts) > 0:
            for host in hosts:
                hostname = host['match']
                if host_name == hostname:
                    return hostname
            return hostname
        LOG.debug("no host found for:" + host_name)
        return None

    @retry_wrapper
    def get_exports_count_by_initiators(self, initiator_ports):
        """Fetches ITL map for a given list of initiator ports
        """
        comma_delimited_initiator_list = ",".join(initiator_ports)
        (s, h) = CoprHD_utils.service_json_request(
            self.configuration.hostname,
            self.configuration.coprhd_port, "GET",
            URI_BLOCK_EXPORTS_FOR_INITIATORS.format(
                comma_delimited_initiator_list),
            None)

        export_itl_maps = CoprHD_utils.json_decode(s)

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
                provisioned_gb = 0.0
                for vpair in vpairs:
                    if vpair:
                        (s, h) = CoprHD_utils.service_json_request(
                            self.configuration.hostname,
                            self.configuration.coprhd_port,
                            "GET",
                            URI_VPOOL_VARRAY_CAPACITY.format(vpair[0],
                                                             vpair[1]),
                            body=None)
                        capacity = CoprHD_utils.json_decode(s)

                        free_gb += float(capacity["free_gb"])
                        used_gb += float(capacity["used_gb"])
                        provisioned_gb += float(capacity["provisioned_gb"])

                self.stats['free_capacity_gb'] = free_gb
                self.stats['total_capacity_gb'] = free_gb + used_gb
                self.stats['reserved_percentage'] = 100 * \
                    provisioned_gb / (free_gb + used_gb)

            return self.stats

        except CoprHD_utils.CoprHdError:
            LOG.error(_("Failed to update volume stats"))
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Update volume stats failed"))

    @retry_wrapper
    def retype(self, ctxt, volume, new_type, diff, host):
        """changes the vpool type"""
        self.authenticate_user()
        volume_name = self._get_coprhd_volume_name(volume)
        vpool_name = new_type['extra_specs']['CoprHD:VPOOL']

        try:
            task = self.volume_obj.update(
                self.configuration.coprhd_tenant +
                "/" +
                self.configuration.coprhd_project,
                volume_name,
                vpool_name)

            self.volume_obj.check_for_sync(task['task'][0], True)
            return True
        except CoprHD_utils.CoprHdError as e:
            if e.err_code == CoprHD_utils.CoprHdError.SOS_FAILURE_ERR:
                raise CoprHD_utils.CoprHdError(
                    CoprHD_utils.CoprHdError.SOS_FAILURE_ERR,
                    "Volume " + volume_name + ": update failed\n" + e.err_text)
            else:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _("Volume : %s type update failed") % volume_name)
