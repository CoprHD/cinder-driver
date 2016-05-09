# Copyright (c)2016 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.

from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
import json
from cinder.volume.drivers.emc.coprhd import volume
from cinder.volume.drivers.emc.coprhd import consistencygroup
from threading import Timer
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError


class Snapshot(object):

    # The class definition for operations on 'Snapshot'.

    # Commonly used URIs for the 'Snapshot' module
    URI_SNAPSHOTS = '/{0}/snapshots/{1}'
    URI_BLOCK_SNAPSHOTS = '/block/snapshots/{0}'
    URI_BLOCK_SNAPSHOTS_SEARCH = '/block/snapshots/search'
    URI_SEARCH_SNAPSHOT_BY_TAG = '/block/snapshots/search?tag={0}'
    URI_BLOCK_SNAPSHOTS_SEARCH_BY_PROJECT_AND_NAME \
        = URI_BLOCK_SNAPSHOTS_SEARCH + "?project={0}&name={1}"
    URI_SNAPSHOT_LIST = '/{0}/{1}/{2}/protection/snapshots'
    URI_SNAPSHOT_EXPORTS = '/{0}/snapshots/{1}/exports'
    URI_SNAPSHOT_VOLUME_EXPORT = '/{0}/snapshots/{1}/exports'
    URI_SNAPSHOT_UNEXPORTS_VOL = URI_SNAPSHOT_EXPORTS + '/{2},{3},{4}'
    URI_SNAPSHOT_RESTORE = '/{0}/snapshots/{1}/restore'
    URI_BLOCK_SNAPSHOTS_ACTIVATE = '/{0}/snapshots/{1}/activate'

    URI_FILE_SNAPSHOT_TASKS = '/{0}/snapshots/{1}/tasks'
    URI_SNAPSHOT_TASKS_BY_OPID = '/vdc/tasks/{0}'

    URI_RESOURCE_DEACTIVATE = '{0}/deactivate'

    URI_CONSISTENCY_GROUP = "/block/consistency-groups"
    URI_CONSISTENCY_GROUPS_SNAPSHOT = URI_CONSISTENCY_GROUP + \
        "/{0}/protection/snapshots"
    URI_CONSISTENCY_GROUPS_SNAPSHOT_INSTANCE \
        = URI_CONSISTENCY_GROUP + "/{0}/protection/snapshots/{1}"
    URI_CONSISTENCY_GROUPS_SNAPSHOT_ACTIVATE \
        = URI_CONSISTENCY_GROUPS_SNAPSHOT_INSTANCE + "/activate"
    URI_CONSISTENCY_GROUPS_SNAPSHOT_DEACTIVATE \
        = URI_CONSISTENCY_GROUPS_SNAPSHOT_INSTANCE + "/deactivate"
    URI_CONSISTENCY_GROUPS_SNAPSHOT_RESTORE \
        = URI_CONSISTENCY_GROUPS_SNAPSHOT_INSTANCE + "/restore"
    URI_CONSISTENCY_GROUPS_SNAPSHOT_RESYNC \
        = URI_CONSISTENCY_GROUPS_SNAPSHOT_INSTANCE + "/resynchronize"

    URI_BLOCK_SNAPSHOTS_TAG = URI_BLOCK_SNAPSHOTS + '/tags'
    URI_CONSISTENCY_GROUP_TAG = URI_CONSISTENCY_GROUP + '/{0}/tags'
    URI_SNAPSHOT_RESYNC = '/{0}/snapshots/{1}/resynchronize'

    URI_VPLEX_SNAPSHOT_IMPORT = '/block/snapshots/{0}/expose'

    SHARES = 'filesystems'
    VOLUMES = 'volumes'
    OBJECTS = 'objects'
    CG = 'consistency-groups'

    BLOCK = 'block'
    OBJECT = 'object'

    TYPE_REPLIC_LIST = ["NATIVE", "RP", "SRDF"]
    BOOLEAN_TYPE = ["true", "false"]

    isTimeout = False
    timeout = 300

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def snapshot_list_uri(self, otype, otypename, ouri):
        '''
        Makes REST API call to list snapshot under a shares or volumes
         parameters:
            otype     : block
            otypename : either volumes or consistency-groups should be provided
            ouri      : uri of volumes or consistency-group

        Returns:
            return list of snapshots
        '''
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            Snapshot.URI_SNAPSHOT_LIST.format(otype, otypename, ouri), None)
        o = common.json_decode(s)
        return o['snapshot']

    def snapshot_show_uri(self, otype, resourceUri, suri, xml=False):
        '''
        Retrieves snapshot details based on snapshot Name or Label
        Parameters:
            otype : block
            suri : uri of the Snapshot.
            resourceUri: uri of the source resource
            typename: volumes or consistency-groups should be provided
        Returns:
            Snapshot details in JSON response payload
        '''
        if(resourceUri is not None and
           resourceUri.find('BlockConsistencyGroup') > 0):
            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "GET",
                Snapshot.URI_CONSISTENCY_GROUPS_SNAPSHOT_INSTANCE.format(
                    resourceUri,
                    suri),
                None,
                None, xml)
        else:
            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "GET",
                Snapshot.URI_SNAPSHOTS.format(otype, suri), None, None, xml)

        if(xml is False):
            return common.json_decode(s)
        return s

    def snapshot_query(self, storageresType,
                       storageresTypename, resuri, snapshotName):
        if(resuri is not None):
            uris = self.snapshot_list_uri(
                storageresType,
                storageresTypename,
                resuri)
            for uri in uris:
                snapshot = self.snapshot_show_uri(
                    storageresType,
                    resuri,
                    uri['id'])
                if(False == (common.get_node_value(snapshot, 'inactive'))):
                    if (snapshot['name'] == snapshotName):
                        return snapshot['id']

        raise SOSError(
            SOSError.SOS_FAILURE_ERR,
            "snapshot with the name:" +
            snapshotName +
            " Not Found")

    def snapshot_show_task_opid(self, otype, snap, taskid):
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            Snapshot.URI_SNAPSHOT_TASKS_BY_OPID.format(taskid),
            None)
        if (not s):
            return None
        o = common.json_decode(s)
        return o

    # Blocks the operation until the task is complete/error out/timeout
    def block_until_complete(self, storageresType, resuri, task_id, synctimeout=0):
        if synctimeout:
            t = Timer(synctimeout, self.timeout_handler)
        else:
            t = Timer(self.timeout, self.timeout_handler)
        t.start()
        while(True):
            #out = self.show_by_uri(id)
            out = self.snapshot_show_task_opid(storageresType, resuri, task_id)

            if(out):
                if(out["state"] == "ready"):
                    # cancel the timer and return
                    t.cancel()
                    break
                # if the status of the task is 'error' then cancel the timer
                # and raise exception
                if(out["state"] == "error"):
                    # cancel the timer
                    t.cancel()
                    error_message = "Please see logs for more details"
                    if("service_error" in out and
                       "details" in out["service_error"]):
                        error_message = out["service_error"]["details"]
                    raise SOSError(
                        SOSError.VALUE_ERR,
                        "Task: " +
                        task_id +
                        " is failed with error: " +
                        error_message)

            if(self.isTimeout):
                print "Operation timed out"
                self.isTimeout = False
                break
        return

    def storageResource_query(self,
                              storageresType,
                              volumeName,
                              cgName,
                              project,
                              tenant):
        resourcepath = "/" + project + "/"
        if(tenant is not None):
            resourcepath = tenant + resourcepath

        resUri = None
        resourceObj = None
        if(Snapshot.BLOCK == storageresType and volumeName is not None):
            resourceObj = volume.Volume(self.__ipAddr, self.__port)
            resUri = resourceObj.volume_query(resourcepath + volumeName)
        elif(Snapshot.BLOCK == storageresType and cgName is not None):
            resourceObj = consistencygroup.ConsistencyGroup(
                self.__ipAddr,
                self.__port)
            resUri = resourceObj.consistencygroup_query(
                cgName,
                project,
                tenant)
        else:
            resourceObj = None

        return resUri

    def snapshot_create(self, otype, typename, ouri,
                        snaplabel, inactive, rptype, sync, readonly=False, synctimeout=0):
        '''new snapshot is created, for a given shares or volumes
            parameters:
                otype      : block
                type should be provided
                typename   : either volume or consistency-groups should be provided
                ouri       : uri of volume
                snaplabel  : name of the snapshot
                activate   : activate snapshot in vnx and vmax
                rptype     : type of replication
        '''

        # check snapshot is already exist
        is_snapshot_exist = True
        try:
            self.snapshot_query(otype, typename, ouri, snaplabel)
        except SOSError as e:
            if(e.err_code == SOSError.NOT_FOUND_ERR):
                is_snapshot_exist = False
            else:
                raise e

        if(is_snapshot_exist):
            raise SOSError(
                SOSError.ENTRY_ALREADY_EXISTS_ERR,
                "Snapshot with name " +
                snaplabel +
                " already exists under " +
                typename)

        body = None

        if(otype == Snapshot.BLOCK):
            parms = {
                'name': snaplabel,
                # if true, the snapshot will not activate the synchronization
                # between source and target volumes
                'create_inactive': inactive
            }
            if(rptype):
                parms['type'] = rptype
            if(readonly == "true"):
                parms['read_only'] = readonly
            body = json.dumps(parms)

        else:
            parms = {
                'name': snaplabel
            }
            if(readonly == "true"):
                parms['read_only'] = readonly
            body = json.dumps(parms)

        # REST api call
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "POST",
            Snapshot.URI_SNAPSHOT_LIST.format(otype, typename, ouri), body)
        o = common.json_decode(s)

        task = None
        if(otype == Snapshot.BLOCK):
            task = o["task"][0]
        else:
            task = o

        if(sync):
            return (
                self.block_until_complete(
                    otype,
                    task['resource']['id'],
                    task["id"], synctimeout)
            )
        else:
            return o

    def snapshot_delete_uri(self, otype, resourceUri, suri, sync, synctimeout):
        '''Delete a snapshot by uri
        parameters:
            otype : block
            suri : Uri of the Snapshot.
        '''
        s = None
        if(resourceUri.find("Volume") > 0):

            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "POST",
                Snapshot.URI_RESOURCE_DEACTIVATE.format(
                    Snapshot.URI_BLOCK_SNAPSHOTS.format(suri)),
                None)
        elif(resourceUri.find("BlockConsistencyGroup") > 0):

            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "POST",
                Snapshot.URI_CONSISTENCY_GROUPS_SNAPSHOT_DEACTIVATE.format(
                    resourceUri,
                    suri),
                None)
        o = common.json_decode(s)
        task = None
        if(otype == Snapshot.BLOCK):
            task = o["task"][0]
        else:
            task = o

        if(sync):
            return (
                self.block_until_complete(
                    otype,
                    task['resource']['id'],
                    task["id"], synctimeout)
            )
        else:
            return o

    def snapshot_delete(self, storageresType,
                        storageresTypename, resourceUri, name, sync, synctimeout=0):
        snapshotUri = self.snapshot_query(
            storageresType,
            storageresTypename,
            resourceUri,
            name)
        self.snapshot_delete_uri(
            storageresType,
            resourceUri,
            snapshotUri,
            sync, synctimeout)
