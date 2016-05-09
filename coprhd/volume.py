#!/usr/bin/python

# Copyright (c) 2016 EMC Corporation
# All Rights Reserved

# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.


from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
import json

from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError
from threading import Timer
from cinder.volume.drivers.emc.coprhd.virtualarray import VirtualArray
from cinder.volume.drivers.emc.coprhd import consistencygroup


class Volume(object):

    '''
    The class definition for operations on 'Volume'.
    '''
    # Commonly used URIs for the 'Volume' module
    URI_SEARCH_VOLUMES = '/block/volumes/search?project={0}'
    URI_SEARCH_VOLUMES_BY_PROJECT_AND_NAME = \
        '/block/volumes/search?project={0}&name={1}'
    URI_SEARCH_VOLUMES_BY_TAG = '/block/volumes/search?tag={0}'
    URI_VOLUMES = '/block/volumes'
    URI_VOLUME = URI_VOLUMES + '/{0}'
    URI_VOLUME_CREATE = URI_VOLUMES + '?project={0}'
    URI_VOLUME_SNAPSHOTS = URI_VOLUME + '/snapshots'
    URI_VOLUME_RESTORE = URI_VOLUME + '/restore'
    URI_VOLUME_EXPORTS = URI_VOLUME + '/exports'
    URI_VOLUME_UNEXPORTS = URI_VOLUME_EXPORTS + '/{1},{2},{3}'
    URI_VOLUME_CONSISTENCYGROUP = URI_VOLUME + '/consistency-group'
    URI_PROJECT_RESOURCES = '/projects/{0}/resources'
    URI_VOLUME_TAGS = URI_VOLUME + '/tags'
    URI_BULK_DELETE = URI_VOLUMES + '/deactivate'
    URI_DEACTIVATE = URI_VOLUME + '/deactivate'
    URI_EXPAND = URI_VOLUME + '/expand'
    URI_TASK_LIST = URI_VOLUME + '/tasks'
    URI_TASK = URI_TASK_LIST + '/{1}'
    URI_TAG_VOLUME = URI_VOLUME + "/tags"
    URI_VOLUME_CHANGE_VPOOL = URI_VOLUMES + "/vpool-change"

    # Protection REST APIs
    URI_VOLUME_PROTECTION_CREATE = \
        '/block/volumes/{0}/protection/continuous'
    URI_VOLUME_PROTECTION_START = \
        '/block/volumes/{0}/protection/continuous/start'
    URI_VOLUME_PROTECTION_STOP = \
        '/block/volumes/{0}/protection/continuous/stop'
    URI_VOLUME_PROTECTION_PAUSE = \
        '/block/volumes/{0}/protection/continuous/pause'
    URI_VOLUME_PROTECTION_RESUME = \
        '/block/volumes/{0}/protection/continuous/resume'
    URI_VOLUME_PROTECTION_FAILOVER = \
        '/block/volumes/{0}/protection/continuous/failover'
    URI_VOLUME_PROTECTION_DELETE = \
        '/block/volumes/{0}/protection/continuous/deactivate'

    '''continuous copy or Mirror protection REST APIs '''
    URI_VOLUME_PROTECTION_MIRROR_LIST = \
        "/block/volumes/{0}/protection/continuous-copies"
    URI_VOLUME_PROTECTION_MIRROR_INSTANCE_START = \
        "/block/volumes/{0}/protection/continuous-copies/start"
    URI_VOLUME_PROTECTION_MIRROR_INSTANCE_STOP = \
        "/block/volumes/{0}/protection/continuous-copies/stop"
    URI_VOLUME_PROTECTION_MIRROR_INSTANCE_PAUSE = \
        "/block/volumes/{0}/protection/continuous-copies/pause"
    URI_VOLUME_PROTECTION_MIRROR_RESUME = \
        "/block/volumes/{0}/protection/continuous-copies/resume"
    URI_VOLUME_PROTECTION_MIRROR_FAILOVER = \
        "/block/volumes/{0}/protection/continuous-copies/failover"
    URI_VOLUME_PROTECTION_MIRROR_FAILOVER_TEST = \
        "/block/volumes/{0}/protection/continuous-copies/failover-test"
    URI_VOLUME_PROTECTION_MIRROR_FAILOVER_CANCEL = \
        "/block/volumes/{0}/protection/continuous-copies/failover-test-cancel"
    URI_VOLUME_PROTECTION_MIRROR_FAILOVER_SWAP = \
        "/block/volumes/{0}/protection/continuous-copies/swap"
    URI_VOLUME_PROTECTION_MIRROR_INSTANCE_DEACTIVATE = \
        "/block/volumes/{0}/protection/continuous-copies/deactivate"
    URI_VOLUME_PROTECTION_MIRROR_INSTANCE_SYNC = \
        "/block/volumes/{0}/protection/continuous-copies/sync"
    URI_VOLUME_PROTECTION_MIRROR_INSTANCE_STOP_PID = \
        "/block/volumes/{0}/protection/native/continuous-copies/{1}/stop/"

    URI_VOLUME_PROTECTION_MIRROR_MID_SHOW = \
        "/block/volumes/{0}/protection/continuous-copies/{1}"
    URI_VOLUME_PROTECTION_MIRROR_FULLCOPY = \
        "/block/volumes/{0}/protection/full-copies"

    # Protection set REST APIs
    URI_VOLUME_PROTECTIONSET_INSTANCE = \
        "/block/volumes/{0}/protection/protection-sets/{1}"
    URI_VOLUME_PROTECTIONSET_RESOURCES = '/block/protection-sets/{0}/resources'
    URI_VOLUME_PROTECTIONSET_DISCOVER = '/block/protection-sets/{0}/discover'

    URI_UNMANAGED_VOLUMES_SHOW = '/vdc/unmanaged/volumes/{0}'
    URI_UNMANAGED_VOLUMES_INGEST = '/vdc/unmanaged/volumes/ingest'
    URI_UNMANAGED_EXPORTED_VOLUMES_INGEST = '/vdc/unmanaged/volumes/ingest-exported'

    # Protection REST APIs - clone
    URI_VOLUME_PROTECTION_FULLCOPIES = \
        '/block/volumes/{0}/protection/full-copies'
    URI_SNAPSHOT_PROTECTION_FULLCOPIES = \
        '/block/snapshots/{0}/protection/full-copies'

    # New URIs Supported

    URI_VOLUME_CLONE_RESTORE = "/block/full-copies/{0}/restore"
    URI_VOLUME_CLONE_RESYNCRONIZE = "/block/full-copies/{0}/resynchronize"
    URI_VOLUME_CLONE_ACTIVATE = "/block/full-copies/{0}/activate"
    URI_VOLUME_CLONE_DETACH = "/block/full-copies/{0}/detach"
    URI_VOLUME_CLONE_CHECKPROGRESS = "/block/full-copies/{0}/check-progress"
    URI_VOLUME_CLONE_LIST = "/block/full-copies"

    # New CG URIs
    URI_CG_CLONE = "/block/consistency-groups/{0}/protection/full-copies"
    URI_CG_CLONE_RESTORE = "/block/consistency-groups/{0}/protection/full-copies/{1}/restore"
    URI_CG_CLONE_RESYNCRONIZE = "/block/consistency-groups/{0}/protection/full-copies/{1}/resynchronize"
    URI_CG_CLONE_ACTIVATE = "/block/consistency-groups/{0}/protection/full-copies/{1}/activate"
    URI_CG_CLONE_DETACH = "/block/consistency-groups/{0}/protection/full-copies/{1}/detach"
    URI_CG_CLONE_DEACTIVATE = "/block/consistency-groups/{0}/protection/full-copies/{1}/deactivate"
    URI_CG_CLONE_LIST = "/block/consistency-groups/{0}/protection/full-copies"
    URI_CG_CLONE_GET = "/block/consistency-groups/{0}/protection/full-copies/{1}"

    # New Migration URIs
    URI_MIGRATION_LIST = "/block/migrations"
    URI_MIGRATION_SHOW = "/block/migrations/{0}"
    URI_MIGRATION_CANCEL = "/block/migrations/{0}/cancel"
    URI_MIGRATION_PAUSE = "/block/migrations/{0}/pause"
    URI_MIGRATION_RESUME = "/block/migrations/{0}/resume"
    URI_MIGRATION_DEACTIVATE = "/block/migrations/{0}/deactivate"

    # New API for adding volumes to RP Journal CG
    URI_RP_JOURNAL_CAPACITY = "/block/volumes/protection/addJournalCapacity"

    VOLUME_PROTECTIONS = ['rp', 'native', 'srdf']
    VOLUME_PROTECTION_HELP = \
        'type of protection(rp or native or srdf) - default:native'

    VOLUME_PROTECTIONS_EX_SRDF = ['rp', 'native']
    VOLUME_PROTECTION_HELP_EX_SRDF = \
        'type of protection(rp or native) - default:native'

    VOLUMES = 'volumes'
    CG = 'consistency-groups'
    BLOCK = 'block'
    SNAPSHOTS = 'snapshots'

    isTimeout = False
    timeout = 300

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    # Lists volumes in a project
    def list_volumes(self, project):
        '''
        Makes REST API call to list volumes under a project
        Parameters:
            project: name of project
        Returns:
            List of volumes uuids in JSON response payload
        '''

        from cinder.volume.drivers.emc.coprhd.project import Project

        proj = Project(self.__ipAddr, self.__port)
        project_uri = proj.project_query(project)

        volume_uris = self.search_volumes(project_uri)
        volumes = []
        for uri in volume_uris:
            volume = self.show_by_uri(uri)
            if(volume):
                volumes.append(volume)
        return volumes

    def search_volumes(self, project_uri):

        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
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
    def show_by_uri(self, uri, show_inactive=False, xml=False):
        '''
        Makes REST API call and retrieves volume details based on UUID
        Parameters:
            uri: UUID of volume
        Returns:
            Volume details in JSON response payload
        '''
        if(xml):
            (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                                 "GET",
                                                 Volume.URI_VOLUME.format(uri),
                                                 None, None, xml)
            return s

        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "GET",
                                             Volume.URI_VOLUME.format(uri),
                                             None)
        o = common.json_decode(s)
        if(show_inactive):
            return o
        inactive = common.get_node_value(o, 'inactive')
        if(inactive is True):
            return None
        return o

    # Creates a volume given label, project, vpool and size
    def create(self, project, label, size, varray, vpool,
               protocol, sync, number_of_volumes, thin_provisioned,
               consistencygroup, synctimeout=0):
        '''
        Makes REST API call to create volume under a project
        Parameters:
            project: name of the project under which the volume will be created
            label: name of volume
            size: size of volume
            varray: name of varray
            vpool: name of vpool
            protocol: protocol used for the volume (FC or iSCSI)
        Returns:
            Created task details in JSON response payload
        '''

        from cinder.volume.drivers.emc.coprhd.project import Project
        proj_obj = Project(self.__ipAddr, self.__port)
        project_uri = proj_obj.project_query(project)

        from cinder.volume.drivers.emc.coprhd.virtualpool import VirtualPool
        vpool_obj = VirtualPool(self.__ipAddr, self.__port)
        vpool_uri = vpool_obj.vpool_query(vpool, "block")

        varray_obj = VirtualArray(self.__ipAddr, self.__port)
        varray_uri = varray_obj.varray_query(varray)

        request = {
            'name': label,
            'size': size,
            'varray': varray_uri,
            'project': project_uri,
            'vpool': vpool_uri
        }
        if(protocol):
            request["protocols"] = protocol
        if(number_of_volumes and number_of_volumes > 1):
            request["count"] = number_of_volumes
        if(thin_provisioned):
            request["thinly_provisioned"] = thin_provisioned
        from cinder.volume.drivers.emc.coprhd.consistencygroup import ConsistencyGroup
        if(consistencygroup):

            cgobj = ConsistencyGroup(self.__ipAddr, self.__port)
            (tenant, project) = common.get_parent_child_from_xpath(project)
            consuri = cgobj.consistencygroup_query(
                consistencygroup,
                project,
                tenant)
            request['consistency_group'] = consuri

        body = json.dumps(request)
        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "POST",
                                             Volume.URI_VOLUMES,
                                             body)
        o = common.json_decode(s)

        if(sync):
            if(number_of_volumes < 2):
                # check task empty
                if (len(o["task"]) > 0):
                    task = o["task"][0]
                    return self.check_for_sync(task, sync, synctimeout)
                else:
                    raise SOSError(
                        SOSError.SOS_FAILURE_ERR,
                        "error: task list is empty, no task response found")
        else:
            return o

    # Blocks the opertaion until the task is complete/error out/timeout
    def check_for_sync(self, result, sync, synctimeout=0):
        if(sync):
            if(len(result["resource"]) > 0):
                resource = result["resource"]
                return (
                    common.block_until_complete("volume", resource["id"],
                                                result["id"], self.__ipAddr,
                                                self.__port, synctimeout)
                )
            else:
                raise SOSError(
                    SOSError.SOS_FAILURE_ERR,
                    "error: task list is empty, no task response found")
        else:
            return result

    # Queries a volume given its name
    def volume_query(self, name):
        '''
        Makes REST API call to query the volume by name
        Parameters:
            name: name of volume
        Returns:
            Volume details in JSON response payload
        '''
        from cinder.volume.drivers.emc.coprhd.project import Project

        if (common.is_uri(name)):
            return name

        (pname, label) = common.get_parent_child_from_xpath(name)
        if(not pname):
            raise SOSError(SOSError.NOT_FOUND_ERR,
                           "Project name  not specified")
        proj = Project(self.__ipAddr, self.__port)
        puri = proj.project_query(pname)
        puri = puri.strip()
        uris = self.search_volumes(puri)
        for uri in uris:
            volume = self.show_by_uri(uri)
            if (volume and 'name' in volume and volume['name'] == label):
                return volume['id']
        raise SOSError(SOSError.NOT_FOUND_ERR, "Volume " +
                       label + ": not found")

    def get_storageAttributes(self, volumeName, cgName, snapshotName=None):
        storageresType = None
        storageresTypeName = None

        if(snapshotName is not None):
            storageresType = Volume.BLOCK
            storageresTypeName = Volume.SNAPSHOTS
        elif(volumeName is not None):
            storageresType = Volume.BLOCK
            storageresTypeName = Volume.VOLUMES
        elif(cgName is not None):
            storageresType = Volume.BLOCK
            storageresTypeName = Volume.CG
        else:
            storageresType = None
            storageresTypeName = None
        return (storageresType, storageresTypeName)

    def storageResource_query(self,
                              storageresType,
                              volumeName,
                              cgName,
                              snapshotName,
                              project,
                              tenant):
        resourcepath = "/" + project + "/"
        if(tenant is not None):
            resourcepath = tenant + resourcepath

        resUri = None
        resourceObj = None

        if(Volume.BLOCK == storageresType and volumeName is not None):
            resUri = self.volume_query(resourcepath + volumeName)
            if(snapshotName is not None):

                from cinder.volume.drivers.emc.coprhd.snapshot import Snapshot
                snapobj = Snapshot(self.__ipAddr, self.__port)
                resUri = snapobj.snapshot_query(storageresType,
                                                Volume.VOLUMES, resUri, snapshotName)

        elif(Volume.BLOCK == storageresType and cgName is not None):
            resourceObj = consistencygroup.ConsistencyGroup(
                self.__ipAddr, self.__port)
            resUri = resourceObj.consistencygroup_query(
                cgName,
                project,
                tenant)
        else:
            resourceObj = None

        return resUri

     # Creates volume(s) from given source volume
    def clone(self, new_vol_name, number_of_volumes, resourceUri, sync, synctimeout=0):
        '''
        Makes REST API call to clone volume
        Parameters:
            project: name of the project under which the volume will be created
            new_vol_name: name of volume
            number_of_volumes: count of volumes
            src_vol_name: name of the source volume
            src_snap_name : name of the source snapshot
            sync: synchronous request
        Returns:
            Created task details in JSON response payload
        '''
        from cinder.volume.drivers.emc.coprhd.snapshot import Snapshot
        snap_obj = Snapshot(self.__ipAddr, self.__port)
        is_snapshot_clone = False
        clone_full_uri = None

        # consistency group
        if(resourceUri.find("BlockConsistencyGroup") > 0):
            clone_full_uri = Volume.URI_CG_CLONE.format(resourceUri)
        elif(resourceUri.find("BlockSnapshot") > 0):
            is_snapshot_clone = True
            clone_full_uri = \
                Volume.URI_SNAPSHOT_PROTECTION_FULLCOPIES.format(resourceUri)
        else:
            clone_full_uri = \
                Volume.URI_VOLUME_PROTECTION_FULLCOPIES.format(resourceUri)

        request = {
            'name': new_vol_name,
            'type': None,
            'count': 1
        }

        if(number_of_volumes and number_of_volumes > 1):
            request["count"] = number_of_volumes

        body = json.dumps(request)
        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "POST",
                                             clone_full_uri,
                                             body)
        o = common.json_decode(s)

        if(sync):
            if(number_of_volumes < 2):
                task = o["task"][0]

                if(is_snapshot_clone):
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

        volumeUri = self.volume_query(name)
        vol = self.show_by_uri(volumeUri)
        # Filtering based on "replicaState" attribute value of Cloned volume.
        # If "replicaState" value is "SYNCHRONIZED" then only Cloned volume
        # would be in detachable state.
        if(vol and 'protection' in vol and
                'full_copies' in vol['protection'] and
                'replicaState' in vol['protection']['full_copies']):
            if(vol['protection']['full_copies']['replicaState'] == 'SYNCHRONIZED'):
                return True
            else:
                return False
        else:
            return False

    def volume_clone_detach(self, resourceUri, name, sync, synctimeout=0):

        volumeUri = self.volume_query(name)

        # consistency group
        if(resourceUri.find("BlockConsistencyGroup") > 0):
            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "POST",
                Volume.URI_CG_CLONE_DETACH.format(
                    resourceUri,
                    volumeUri), None)
        else:
            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "POST",
                Volume.URI_VOLUME_CLONE_DETACH.format(volumeUri), None)

        o = common.json_decode(s)
        if(sync):
            task = o["task"][0]
            return self.check_for_sync(task, sync, synctimeout)
        else:
            return o

    # Shows volume information given its name
    def show(self, name, show_inactive=False, xml=False):
        '''
        Retrieves volume details based on volume name
        Parameters:
            name: name of the volume. If the volume is under a project,
            then full XPath needs to be specified.
            Example: If VOL1 is a volume under project PROJ1, then the name
            of volume is PROJ1/VOL1
        Returns:
            Volume details in JSON response payload
        '''
        from cinder.volume.drivers.emc.coprhd.project import Project

        if (common.is_uri(name)):
            return name
        (pname, label) = common.get_parent_child_from_xpath(name)
        if (pname is None):
            raise SOSError(SOSError.NOT_FOUND_ERR, "Volume " +
                           str(name) + ": not found")

        proj = Project(self.__ipAddr, self.__port)
        puri = proj.project_query(pname)
        puri = puri.strip()

        uris = self.search_volumes(puri)

        for uri in uris:
            volume = self.show_by_uri(uri, show_inactive)
            if (volume and 'name' in volume and volume['name'] == label):
                if(not xml):
                    return volume
                else:
                    return self.show_by_uri(volume['id'],
                                            show_inactive, xml)
        raise SOSError(SOSError.NOT_FOUND_ERR, "Volume " +
                       str(label) + ": not found")

    def expand(self, name, new_size, sync=False, synctimeout=0):

        #volume_uri = self.volume_query(name)
        volume_detail = self.show(name)
        from decimal import Decimal
        new_size_in_gb = Decimal(Decimal(new_size) / (1024 * 1024 * 1024))
        current_size = Decimal(volume_detail["provisioned_capacity_gb"])
        if(new_size_in_gb <= current_size):
            raise SOSError(
                SOSError.VALUE_ERR,
                "error: Incorrect value of new size: " + str(new_size_in_gb) +
                " GB\nNew size must be greater than current size: " +
                str(current_size) + " GB")

        body = json.dumps({
            "new_size": new_size
        })

        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "POST",
                                             Volume.URI_EXPAND.format(
                                                 volume_detail["id"]),
                                             body)
        if(not s):
            return None
        o = common.json_decode(s)

        if(sync):
            return self.check_for_sync(o, sync, synctimeout)
        return o

    # Deletes a volume given a volume name
    def delete(self, name, volume_name_list=None, sync=False,
               forceDelete=False, vipronly=False, synctimeout=0):
        '''
        Deletes a volume based on volume name
        Parameters:
            name: name of volume if volume_name_list is None
                     otherwise it will be name of project
        '''
        if(volume_name_list is None):
            volume_uri = self.volume_query(name)
            return self.delete_by_uri(volume_uri, sync, forceDelete, vipronly, synctimeout)
        else:
            vol_uris = []
            invalid_vol_names = ""
            for vol_name in volume_name_list:
                try:
                    volume_uri = self.volume_query(name + '/' + vol_name)
                    vol_uris.append(volume_uri)
                except SOSError as e:
                    if(e.err_code == SOSError.NOT_FOUND_ERR):
                        invalid_vol_names += vol_name + " "
                        continue
                    else:
                        raise e

            if(len(vol_uris) > 0):
                self.delete_bulk_uris(vol_uris, forceDelete, vipronly)

            if(len(invalid_vol_names) > 0):
                raise SOSError(SOSError.NOT_FOUND_ERR, "Volumes: " +
                               str(invalid_vol_names) + " not found")

    # Deletes a volume given a volume uri
    def delete_by_uri(self, uri, sync=False,
                      forceDelete=False, vipronly=False, synctimeout=0):
        '''
        Deletes a volume based on volume uri
        Parameters:
            uri: uri of volume
        '''
        params = ''
        if (forceDelete):
            params += '&' if ('?' in params) else '?'
            params += "force=" + "true"
        if (vipronly == True):
            params += '&' if ('?' in params) else '?'
            params += "type=" + 'VIPR_ONLY'

        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "POST",
                                             Volume.URI_DEACTIVATE.format(
                                                 uri) + params,
                                             None)
        if(not s):
            return None
        o = common.json_decode(s)
        if(sync):
            return self.check_for_sync(o, sync, synctimeout)
        return o

    def delete_bulk_uris(self, uris, forceDelete, vipronly):
        '''
        Deletes all the volumes given in the uris
        Parameters:
            uris: uris of volume
        '''
        params = ''
        if (forceDelete):
            params += '&' if ('?' in params) else '?'
            params += "force=" + "true"
        if (vipronly == True):
            params += '&' if ('?' in params) else '?'
            params += "type=" + 'VIPR_ONLY'

        body = json.dumps({'id': uris})

        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "POST",
                                             Volume.URI_BULK_DELETE + params,
                                             body)
        o = common.json_decode(s)
        return o

    # Gets the exports info given a volume uri
    def get_exports_by_uri(self, uri):
        '''
        Makes REST API call to get exports info of a volume
        Parameters:
            uri: URI of the volume
        Returns:
            Exports details in JSON response payload
        '''
        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "GET",
                                             Volume.URI_VOLUME_EXPORTS.format(
                                                 uri),
                                             None)
        return common.json_decode(s)

    # Update a volume information
    # Changed the volume vpool
    def update(self, prefix_path, name, vpool):
        '''
        Makes REST API call to update a volume information
        Parameters:
            name: name of the volume to be updated
            vpool: name of vpool
        Returns
            Created task details in JSON response payload
        '''
        namelist = []

        if type(name) is list:
            namelist = name
        else:
            namelist.append(name)

        volumeurilist = []

        for item in namelist:
            volume_uri = self.volume_query(prefix_path + "/" + item)
            volumeurilist.append(volume_uri)

        from cinder.volume.drivers.emc.coprhd.virtualpool import VirtualPool

        vpool_obj = VirtualPool(self.__ipAddr, self.__port)
        vpool_uri = vpool_obj.vpool_query(vpool, "block")

        params = {
            'vpool': vpool_uri,
            'volumes': volumeurilist
        }

        body = json.dumps(params)

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "POST",
            Volume.URI_VOLUME_CHANGE_VPOOL,
            body)

        o = common.json_decode(s)
        return o

    def mirror_protection_list(self, volume):
        '''
        block mirror list for a given volume name
        Parameters:
            volume: Name of the volume
        Returns:
            result of the action.
        '''
        vol_uri = self.volume_query(volume)

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            Volume.URI_VOLUME_PROTECTION_MIRROR_LIST.format(vol_uri),
            None)
        o = common.json_decode(s)

        mirrorlist = []
        for uri in common.get_node_value(o, 'mirror'):
            mirrorlist.append(uri['id'])
        return mirrorlist

    def get_uri_mirror_protection_vol(self, vol_uri, mirror_uri):
        '''
        get block mirror volume details by mirror volume uri
        Parameters:
            volume uri   : Name of the volume
            mirrorvol uri: Name of the mirror volume

        Returns:
            result of the action.
        '''

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            Volume.URI_VOLUME_PROTECTION_MIRROR_MID_SHOW.format(
                vol_uri, mirror_uri),
            None)
        o = common.json_decode(s)
        if(o['inactive']):
            return None
        return o

    def mirror_volume_query(self, volume, mirrorvolname):
        if (common.is_uri(mirrorvolname)):
            return mirrorvolname

        vol_uri = self.volume_query(volume)
        uris = self.mirror_protection_list(volume)
        for uri in uris:
            mirvol = self.get_uri_mirror_protection_vol(vol_uri, uri)
            if(mirvol is not None and mirvol['name'] == mirrorvolname):
                return mirvol['id']
        raise SOSError(SOSError.NOT_FOUND_ERR, "MirrorVolumeName " +
                       mirrorvolname + ": not found")
