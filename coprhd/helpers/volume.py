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

import oslo_serialization
import six

from cinder.i18n import _
from cinder.volume.drivers.coprhd.helpers import commoncoprhdapi as common
from cinder.volume.drivers.coprhd.helpers import consistencygroup
from cinder.volume.drivers.coprhd.helpers import virtualarray


class Volume(common.CoprHDResource):

    # Commonly used URIs for the 'Volume' module
    URI_SEARCH_VOLUMES = '/block/volumes/search?project={0}'
    URI_SEARCH_VOLUMES_BY_TAG = '/block/volumes/search?tag={0}'
    URI_VOLUMES = '/block/volumes'
    URI_VOLUME = URI_VOLUMES + '/{0}'
    URI_VOLUME_EXPORTS = URI_VOLUME + '/exports'
    URI_BULK_DELETE = URI_VOLUMES + '/deactivate'
    URI_DEACTIVATE = URI_VOLUME + '/deactivate'
    URI_EXPAND = URI_VOLUME + '/expand'
    URI_TAG_VOLUME = URI_VOLUME + "/tags"
    URI_VOLUME_CHANGE_VPOOL = URI_VOLUMES + "/vpool-change"

    # Protection REST APIs - clone
    URI_VOLUME_PROTECTION_FULLCOPIES = (
        '/block/volumes/{0}/protection/full-copies')
    URI_SNAPSHOT_PROTECTION_FULLCOPIES = (
        '/block/snapshots/{0}/protection/full-copies')

    URI_VOLUME_CLONE_DETACH = "/block/full-copies/{0}/detach"

    # New CG URIs
    URI_CG_CLONE = "/block/consistency-groups/{0}/protection/full-copies"
    URI_CG_CLONE_DETACH = (
        "/block/consistency-groups/{0}/protection/full-copies/{1}/detach")

    VOLUMES = 'volumes'
    CG = 'consistency-groups'
    BLOCK = 'block'
    SNAPSHOTS = 'snapshots'

    isTimeout = False
    timeout = 300

    # Lists volumes in a project
    def list_volumes(self, project):
        """Makes REST API call to list volumes under a project

        Parameters:
            project: name of project
        Returns:
            List of volumes uuids in JSON response payload
        """

        volume_uris = self.search_volumes(project)
        volumes = []
        for uri in volume_uris:
            volume = self.show_by_uri(uri)
            if volume:
                volumes.append(volume)
        return volumes

    def search_volumes(self, project):

        from cinder.volume.drivers.coprhd.helpers.project import Project
        proj = Project(self.ipaddr, self.port)
        project_uri = proj.project_query(project)

        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "GET",
                                             Volume.URI_SEARCH_VOLUMES.format(
                                                 project_uri),
                                             None)
        o = common.json_decode(s)
        if not o:
            return []

        volume_uris = []
        resources = common.get_node_value(o, "resource")
        for resource in resources:
            volume_uris.append(resource["id"])
        return volume_uris

    # Shows volume information given its uri
    def show_by_uri(self, uri):
        """Makes REST API call and retrieves volume details based on UUID

        Parameters:
            uri: UUID of volume
        Returns:
            Volume details in JSON response payload
        """

        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "GET",
                                             Volume.URI_VOLUME.format(uri),
                                             None)
        o = common.json_decode(s)
        inactive = common.get_node_value(o, 'inactive')
        if inactive:
            return None
        return o

    # Creates a volume given label, project, vpool and size
    def create(self, project, label, size, varray, vpool,
               sync, consistencygroup, synctimeout=0):
        """Makes REST API call to create volume under a project

        Parameters:
            project          : name of the project under which the volume will
                               be created
            label            : name of volume
            size             : size of volume
            varray           : name of varray
            vpool            : name of vpool
            sync             : synchronous request
            consistencygroup : To create volume under a consistencygroup
            synctimeout      : Query for task status for "synctimeout" secs.
                               If the task doesn't complete in synctimeout
                               secs, an exception is thrown
        Returns:
            Created task details in JSON response payload
        """

        from cinder.volume.drivers.coprhd.helpers.project import Project
        proj_obj = Project(self.ipaddr, self.port)
        project_uri = proj_obj.project_query(project)

        from cinder.volume.drivers.coprhd.helpers.virtualpool import (
            VirtualPool)
        vpool_obj = VirtualPool(self.ipaddr, self.port)
        vpool_uri = vpool_obj.vpool_query(vpool, "block")

        varray_obj = virtualarray.VirtualArray(self.ipaddr, self.port)
        varray_uri = varray_obj.varray_query(varray)

        request = {
            'name': label,
            'size': size,
            'varray': varray_uri,
            'project': project_uri,
            'vpool': vpool_uri,
            'count': 1
        }
        if consistencygroup:
            request['consistency_group'] = consistencygroup

        body = oslo_serialization.jsonutils.dumps(request)
        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "POST",
                                             Volume.URI_VOLUMES,
                                             body)
        o = common.json_decode(s)

        if sync:
            # check task empty
            if len(o["task"]) > 0:
                task = o["task"][0]
                return self.check_for_sync(task, sync, synctimeout)
            else:
                raise common.CoprHdError(
                    common.CoprHdError.SOS_FAILURE_ERR,
                    _("error: task list is empty, no task response found"))
        else:
            return o

    # Blocks the operation until the task is complete/error out/timeout
    def check_for_sync(self, result, sync, synctimeout=0):
        if sync:
            if len(result["resource"]) > 0:
                resource = result["resource"]
                return (
                    common.block_until_complete("volume", resource["id"],
                                                result["id"], self.ipaddr,
                                                self.port, synctimeout)
                )
            else:
                raise common.CoprHdError(
                    common.CoprHdError.SOS_FAILURE_ERR,
                    _("error: task list is empty, no task response found"))
        else:
            return result

    # Queries a volume given its name
    def volume_query(self, name):
        """Makes REST API call to query the volume by name

        Parameters:
            name: name of volume
        Returns:
            Volume details in JSON response payload
        """
        if common.is_uri(name):
            return name

        (pname, label) = common.get_parent_child_from_xpath(name)
        if not pname:
            raise common.CoprHdError(common.CoprHdError.NOT_FOUND_ERR,
                                     _("Project name not specified"))
        uris = self.search_volumes(pname)
        for uri in uris:
            volume = self.show_by_uri(uri)
            if volume and 'name' in volume and volume['name'] == label:
                return volume['id']
        raise common.CoprHdError(common.CoprHdError.NOT_FOUND_ERR,
                                 (_("Volume"
                                    "%s: not found"), label))

    def get_storageAttributes(self, volume_name, cg_name, snapshot_name=None):
        storageres_type = None
        storageres_typename = None

        if snapshot_name is not None:
            storageres_type = Volume.BLOCK
            storageres_typename = Volume.SNAPSHOTS
        elif volume_name is not None:
            storageres_type = Volume.BLOCK
            storageres_typename = Volume.VOLUMES
        elif cg_name is not None:
            storageres_type = Volume.BLOCK
            storageres_typename = Volume.CG
        else:
            storageres_type = None
            storageres_typename = None
        return (storageres_type, storageres_typename)

    def storage_resource_query(self,
                               storageres_type,
                               volume_name,
                               cg_name,
                               snapshot_name,
                               project,
                               tenant):
        resourcepath = "/" + project + "/"
        if tenant is not None:
            resourcepath = tenant + resourcepath

        resUri = None
        resourceObj = None

        if Volume.BLOCK == storageres_type and volume_name is not None:
            resUri = self.volume_query(resourcepath + volume_name)
            if snapshot_name is not None:

                from cinder.volume.drivers.coprhd.helpers.snapshot import (
                    Snapshot)
                snapobj = Snapshot(self.ipaddr, self.port)
                resUri = snapobj.snapshot_query(storageres_type,
                                                Volume.VOLUMES, resUri,
                                                snapshot_name)

        elif Volume.BLOCK == storageres_type and cg_name is not None:
            resourceObj = consistencygroup.ConsistencyGroup(
                self.ipaddr, self.port)
            resUri = resourceObj.consistencygroup_query(
                cg_name,
                project,
                tenant)
        else:
            resourceObj = None

        return resUri

    # Creates volume(s) from given source volume
    def clone(self, new_vol_name, resource_uri,
              sync, synctimeout=0):
        """Makes REST API call to clone volume

        Parameters:
            new_vol_name     : name of volume
            resource_uri      : uri of source volume
            sync             : synchronous request
            synctimeout      : Query for task status for "synctimeout" secs.
                               If the task doesn't complete in synctimeout
                               secs, an exception is thrown

        Returns:
            Created task details in JSON response payload
        """

        from cinder.volume.drivers.coprhd.helpers.snapshot import Snapshot
        snap_obj = Snapshot(self.ipaddr, self.port)
        is_snapshot_clone = False
        clone_full_uri = None

        # consistency group
        if resource_uri.find("BlockConsistencyGroup") > 0:
            clone_full_uri = Volume.URI_CG_CLONE.format(resource_uri)
        elif resource_uri.find("BlockSnapshot") > 0:
            is_snapshot_clone = True
            clone_full_uri = (
                Volume.URI_SNAPSHOT_PROTECTION_FULLCOPIES.format(resource_uri))
        else:
            clone_full_uri = (
                Volume.URI_VOLUME_PROTECTION_FULLCOPIES.format(resource_uri))

        request = {
            'name': new_vol_name,
            'type': None,
            'count': 1
        }

        request["count"] = 1

        body = oslo_serialization.jsonutils.dumps(request)
        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "POST",
                                             clone_full_uri,
                                             body)
        o = common.json_decode(s)

        if sync:
            task = o["task"][0]

            if is_snapshot_clone:
                return (
                    snap_obj.block_until_complete(
                        "block",
                        task["resource"]["id"],
                        task["id"])
                )
            else:
                return self.check_for_sync(task, sync, synctimeout)
        else:
            return o

    # To check whether a cloned volume is in detachable state or not
    def is_volume_detachable(self, name):

        volume_uri = self.volume_query(name)
        vol = self.show_by_uri(volume_uri)
        # Filtering based on "replicaState" attribute value of Cloned volume.
        # If "replicaState" value is "SYNCHRONIZED" then only Cloned volume
        # would be in detachable state.
        if(vol and 'protection' in vol and
                'full_copies' in vol['protection'] and
                'replicaState' in vol['protection']['full_copies']):
            if(vol['protection']['full_copies']['replicaState'] ==
               'SYNCHRONIZED'):
                return True
            return False
        return False

    def volume_clone_detach(self, resource_uri, name, sync, synctimeout=0):

        volume_uri = self.volume_query(name)

        # consistency group
        if resource_uri.find("BlockConsistencyGroup") > 0:
            (s, h) = common.service_json_request(
                self.ipaddr, self.port,
                "POST",
                Volume.URI_CG_CLONE_DETACH.format(
                    resource_uri,
                    volume_uri), None)
        else:
            (s, h) = common.service_json_request(
                self.ipaddr, self.port,
                "POST",
                Volume.URI_VOLUME_CLONE_DETACH.format(volume_uri), None)

        o = common.json_decode(s)
        if sync:
            task = o["task"][0]
            return self.check_for_sync(task, sync, synctimeout)
        else:
            return o

    # Shows volume information given its name
    def show(self, name):
        """Retrieves volume details based on volume name

        Parameters:
            name: name of the volume. If the volume is under a project,
            then full XPath needs to be specified.
            Example: If VOL1 is a volume under project PROJ1, then the name
            of volume is PROJ1/VOL1
        Returns:
            Volume details in JSON response payload
        """
        if common.is_uri(name):
            return name
        (pname, label) = common.get_parent_child_from_xpath(name)
        if pname is None:
            raise common.CoprHdError(common.CoprHdError.NOT_FOUND_ERR,
                                     (_("Volume %s : not found"),
                                      six.text_type(name)))

        uris = self.search_volumes(pname)

        for uri in uris:
            volume = self.show_by_uri(uri)
            if volume and 'name' in volume and volume['name'] == label:
                return volume
        raise common.CoprHdError(common.CoprHdError.NOT_FOUND_ERR,
                                 (_("Volume"
                                    " %s : not found"), six.text_type(label)))

    def expand(self, name, new_size, sync=False, synctimeout=0):

        volume_detail = self.show(name)
        from decimal import Decimal
        new_size_in_gb = Decimal(Decimal(new_size) / (1024 * 1024 * 1024))
        current_size = Decimal(volume_detail["provisioned_capacity_gb"])
        if new_size_in_gb <= current_size:
            raise common.CoprHdError(
                common.CoprHdError.VALUE_ERR,
                (_("error: Incorrect value of new size: %(new_size_in_gb)s"
                   " GB\nNew size must be greater than current size: "
                   "%(current_size)s GB"), {'new_size_in_gb': new_size_in_gb,
                                            'current_size': current_size}))

        body = oslo_serialization.jsonutils.dumps({
            "new_size": new_size
        })

        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "POST",
                                             Volume.URI_EXPAND.format(
                                                 volume_detail["id"]),
                                             body)
        if not s:
            return None
        o = common.json_decode(s)

        if sync:
            return self.check_for_sync(o, sync, synctimeout)
        return o

    # Deletes a volume given a volume name
    def delete(self, name, sync=False,
               force_delete=False, coprhdonly=False, synctimeout=0):
        """Deletes a volume based on volume name

        Parameters:
            name        : name of volume to be deleted
            sync        : synchronous request
            force_delete : if true, it will force the delete of internal
                          volumes that have the SUPPORTS_FORCE flag
            coprhdonly  : to delete volumes from coprHD only
            synctimeout : Query for task status for "synctimeout" secs. If
                          the task doesn't complete in synctimeout secs, an
                          exception is thrown

        """
        volume_uri = self.volume_query(name)
        return self.delete_by_uri(volume_uri, sync, force_delete,
                                  coprhdonly, synctimeout)

    # Deletes a volume given a volume uri
    def delete_by_uri(self, uri, sync=False,
                      force_delete=False, coprhdonly=False, synctimeout=0):
        """Deletes a volume based on volume uri

        Parameters:
            uri: uri of volume
        """

        params = ''
        if force_delete:
            params += '&' if ('?' in params) else '?'
            params += "force=" + "true"
        if coprhdonly is True:
            params += '&' if ('?' in params) else '?'
            params += "type=" + 'CoprHD_ONLY'

        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "POST",
                                             Volume.URI_DEACTIVATE.format(
                                                 uri) + params,
                                             None)
        if not s:
            return None
        o = common.json_decode(s)
        if sync:
            return self.check_for_sync(o, sync, synctimeout)
        return o

    # Gets the exports info given a volume uri
    def get_exports_by_uri(self, uri):
        """Makes REST API call to get exports info of a volume

        Parameters:
            uri: URI of the volume
        Returns:
            Exports details in JSON response payload
        """
        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "GET",
                                             Volume.URI_VOLUME_EXPORTS.format(
                                                 uri),
                                             None)
        return common.json_decode(s)

    # Update a volume information
    # Changed the volume vpool
    def update(self, prefix_path, name, vpool):
        """Makes REST API call to update a volume information

        Parameters:
            name: name of the volume to be updated
            vpool: name of vpool
        Returns
            Created task details in JSON response payload
        """
        namelist = []

        if type(name) is list:
            namelist = name
        else:
            namelist.append(name)

        volumeurilist = []

        for item in namelist:
            volume_uri = self.volume_query(prefix_path + "/" + item)
            volumeurilist.append(volume_uri)

        from cinder.volume.drivers.coprhd.helpers.virtualpool import (
            VirtualPool)

        vpool_obj = VirtualPool(self.ipaddr, self.port)
        vpool_uri = vpool_obj.vpool_query(vpool, "block")

        params = {
            'vpool': vpool_uri,
            'volumes': volumeurilist
        }

        body = oslo_serialization.jsonutils.dumps(params)

        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "POST",
            Volume.URI_VOLUME_CHANGE_VPOOL,
            body)

        o = common.json_decode(s)
        return o
