#!/usr/bin/python

# Copyright (c) 2016 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.


# import python system modules

from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.volume import Volume
from cinder.volume.drivers.emc.coprhd.snapshot import Snapshot
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError
from cinder.volume.drivers.emc.coprhd.project import Project
from cinder.volume.drivers.emc.coprhd.cluster import Cluster
from cinder.volume.drivers.emc.coprhd.host import Host
from cinder.volume.drivers.emc.coprhd.virtualarray import VirtualArray
import json


class ExportGroup(object):

    '''
    The class definition for operations on 'Export group Service'.
    '''
    URI_EXPORT_GROUP = "/block/exports"
    URI_EXPORT_GROUPS_SHOW = URI_EXPORT_GROUP + "/{0}"
    URI_EXPORT_GROUP_LIST = '/projects/{0}/resources'
    URI_EXPORT_GROUP_SEARCH = '/block/exports/search'
    URI_EXPORT_GROUP_DEACTIVATE = URI_EXPORT_GROUPS_SHOW + '/deactivate'
    URI_EXPORT_GROUP_UPDATE = '/block/exports/{0}'
    URI_EXPORT_GROUP_TASKS_LIST = '/block/exports/{0}/tasks'
    URI_EXPORT_GROUP_TASK = URI_EXPORT_GROUP_TASKS_LIST + '/{1}'
    # 'Exclusive' is for backward compatibility only
    EXPORTGROUP_TYPE = ['Initiator', 'Host', 'Cluster', 'Exclusive']
    URI_EXPORT_GROUP_TAG = URI_EXPORT_GROUPS_SHOW + '/tags'

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    '''
    Remove volumes from the exportgroup, given the uris of volume.
    '''

    def exportgroup_remove_volumes_by_uri(self, exportgroup_uri, volumeIdList,
                                          sync=False, tenantname=None,
                                          projectname=None, snapshots=None,
                                          cg=None, synctimeout=0):
        # if snapshot given then snapshot added to exportgroup
        volume_snapshots = volumeIdList
        if(snapshots):
            resuri = None
            if(cg):
                blockTypeName = 'consistency-groups'
                from cinder.volume.drivers.emc.coprhd.consistencygroup import ConsistencyGroup
                cgObject = ConsistencyGroup(self.__ipAddr, self.__port)
                resuri = cgObject.consistencygroup_query(cg, projectname,
                                                         tenantname)
            else:
                blockTypeName = 'volumes'
                if(len(volumeIdList) > 0):
                    resuri = volumeIdList[0]
            volume_snapshots = []
            snapshotObject = Snapshot(self.__ipAddr, self.__port)
            for snapshot in snapshots:
                volume_snapshots.append(
                    snapshotObject.snapshot_query(
                        'block', blockTypeName, resuri, snapshot))

        parms = {}

        parms['volume_changes'] = self._remove_list(volume_snapshots)
        o = self.send_json_request(exportgroup_uri, parms)
        return self.check_for_sync(o, sync, synctimeout)

    # initiator
        '''
        add initiator to export group
        parameters:
           exportgroupname     : Name/id of the export group.
           tenantname          : tenant name
           projectname         : name of project
           initator            : name of initiator
           hostlabel           : name of host or host label
        return
            return action result
         '''

    def _remove_list(self, uris):
        resChanges = {}
        if(not isinstance(uris, list)):
            resChanges['remove'] = [uris]
        else:
            resChanges['remove'] = uris
        return resChanges

    def send_json_request(self, exportgroup_uri, param):
        body = json.dumps(param)
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "PUT",
            self.URI_EXPORT_GROUP_UPDATE.format(exportgroup_uri), body)
        return common.json_decode(s)

    def check_for_sync(self, result, sync, synctimeout=0):
        if(sync):
            if(len(result["resource"]) > 0):
                resource = result["resource"]
                return (
                    common.block_until_complete("export", resource["id"],
                                                result["id"], self.__ipAddr,
                                                self.__port, synctimeout)
                )
            else:
                raise SOSError(
                    SOSError.SOS_FAILURE_ERR,
                    "error: task list is empty, no task response found")
        else:
            return result

    def exportgroup_list(self, project, tenant):
        '''
        This function will give us the list of export group uris
        separated by comma.
        parameters:
            project: Name of the project path.
        return
            returns with list of export group ids separated by comma.
        '''
        if(tenant is None):
            tenant = ""
        projobj = Project(self.__ipAddr, self.__port)
        fullproj = tenant + "/" + project
        projuri = projobj.project_query(fullproj)

        uri = self.URI_EXPORT_GROUP_SEARCH

        if ('?' in uri):
            uri += '&project=' + projuri
        else:
            uri += '?project=' + projuri

        (s, h) = common.service_json_request(self.__ipAddr, self.__port, "GET",
                                             uri, None)
        o = common.json_decode(s)
        if not o:
            return []

        exportgroups = []
        resources = common.get_node_value(o, "resource")
        for resource in resources:
            exportgroups.append(resource["id"])

        return exportgroups

    def exportgroup_show(self, name, project, tenant, varray=None, xml=False):
        '''
        This function will take export group name and project name as input and
        It will display the Export group with details.
        parameters:
           name : Name of the export group.
           project: Name of the project.
        return
            returns with Details of export group.
        '''
        varrayuri = None
        if(varray):
            varrayObject = VirtualArray(self.__ipAddr, self.__port)
            varrayuri = varrayObject.varray_query(varray)
        uri = self.exportgroup_query(name, project, tenant, varrayuri)
        (s, h) = common.service_json_request(
            self.__ipAddr,
            self.__port,
            "GET",
            self.URI_EXPORT_GROUPS_SHOW.format(uri), None)
        o = common.json_decode(s)
        if(o['inactive']):
            return None

        if(not xml):
            return o

        (s, h) = common.service_json_request(
            self.__ipAddr,
            self.__port,
            "GET",
            self.URI_EXPORT_GROUPS_SHOW.format(uri),
            None, None, xml)

        return s

    def exportgroup_create(self, name, project, tenant, varray,
                           exportgrouptype, export_destination=None):
        '''
        This function will take export group name and project name  as input
        and it will create the Export group with given name.
        parameters:
           name : Name of the export group.
           project: Name of the project path.
           tenant: Container tenant name.
        return
            returns with status of creation.
        '''
        # check for existence of export group.
        try:
            status = self.exportgroup_show(name, project, tenant)
        except SOSError as e:
            if(e.err_code == SOSError.NOT_FOUND_ERR):
                if(tenant is None):
                    tenant = ""

                fullproj = tenant + "/" + project
                projObject = Project(self.__ipAddr, self.__port)
                projuri = projObject.project_query(fullproj)

                varrayObject = VirtualArray(self.__ipAddr, self.__port)
                nhuri = varrayObject.varray_query(varray)

                parms = {
                    'name': name,
                    'project': projuri,
                    'varray': nhuri,
                    'type': exportgrouptype
                }

                if(exportgrouptype and export_destination):
                    if (exportgrouptype == 'Cluster'):
                        cluster_obj = Cluster(self.__ipAddr, self.__port)
                        try:
                            cluster_uri = cluster_obj.cluster_query(
                                export_destination,
                                fullproj)
                        except SOSError as e:
                            raise e
                        parms['clusters'] = [cluster_uri]
                    elif (exportgrouptype == 'Host'):
                        host_obj = Host(self.__ipAddr, self.__port)
                        try:
                            host_uri = host_obj.query_by_name(
                                export_destination)
                        except SOSError as e:
                            raise e
                        parms['hosts'] = [host_uri]

                body = json.dumps(parms)
                (s, h) = common.service_json_request(self.__ipAddr,
                                                     self.__port, "POST",
                                                     self.URI_EXPORT_GROUP,
                                                     body)

                o = common.json_decode(s)
                return o
            else:
                raise e

        if(status):
            raise SOSError(
                SOSError.ENTRY_ALREADY_EXISTS_ERR,
                "Export group with name " + name +
                " already exists")

    def exportgroup_query(self, name, project, tenant, varrayuri=None):
        '''
        This function will take export group name/id and project name  as input
        and returns export group id.
        parameters:
           name : Name/id of the export group.
        return
            return with id of the export group.
         '''
        if (common.is_uri(name)):
            return name

        uris = self.exportgroup_list(project, tenant)
        for uri in uris:
            exportgroup = self.exportgroup_show(uri, project, tenant)
            if(exportgroup):
                if (exportgroup['name'] == name):
                    if(varrayuri):
                        varrayobj = exportgroup['varray']
                        if(varrayobj['id'] == varrayuri):
                            return exportgroup['id']
                        else:
                            continue
                    else:
                        return exportgroup['id']
        raise SOSError(
            SOSError.NOT_FOUND_ERR,
            "Export Group " + name + ": not found")

    def exportgroup_add_volumes(self, sync, exportgroupname, tenantname,
                                maxpaths, minpaths, pathsperinitiator,
                                projectname, volumenames, snapshots=None,
                                cg=None, blockmirror=None, synctimeout=0, varray=None):
        '''
        add volume to export group
        parameters:
           exportgroupname : Name/id of the export group.
           tenantname      : tenant name
           projectname     : name of project
           volumename      : name of volume that needs
                             to be added to exportgroup
           lunid           : lun id
        return
            return action result
        '''
        varrayuri = None
        if(varray):
            varrayObject = VirtualArray(self.__ipAddr, self.__port)
            varrayuri = varrayObject.varray_query(varray)

        exportgroup_uri = self.exportgroup_query(exportgroupname,
                                                 projectname, tenantname, varrayuri)

        # get volume uri
        if(tenantname is None):
            tenantname = ""
        # List of volumes.
        # incase of snapshots from volume, this will hold the source volume
        # URI.
        volume_snapshots = []

        if(volumenames):
            volume_snapshots = self._get_resource_lun_tuple(
                volumenames, "volumes", None, tenantname,
                projectname, None)

        # Block mirror function
        if(blockmirror and len(blockmirror) > 0):
            resuri = None

            blockTypeName = 'volumes'
            if(len(volume_snapshots) > 0):
                resuri = volume_snapshots[0]['id']

            volume_snapshots = self._get_resource_lun_tuple(
                blockmirror, "blockmirror", resuri, tenantname,
                projectname, blockTypeName)

        # if snapshot given then snapshot added to exportgroup
        if(snapshots and len(snapshots) > 0):
            resuri = None
            if(cg):
                blockTypeName = 'consistency-groups'
                from cinder.volume.drivers.emc.coprhd.consistencygroup import ConsistencyGroup
                cgObject = ConsistencyGroup(self.__ipAddr, self.__port)
                resuri = cgObject.consistencygroup_query(cg, projectname,
                                                         tenantname)
            else:
                blockTypeName = 'volumes'
                if(len(volume_snapshots) > 0):
                    resuri = volume_snapshots[0]['id']

            volume_snapshots = self._get_resource_lun_tuple(
                snapshots, "snapshots", resuri, tenantname,
                projectname, blockTypeName)

        parms = {}
        # construct the body

        volChanges = {}
        volChanges['add'] = volume_snapshots
        path_parameters = {}

        if (maxpaths):
            path_parameters['max_paths'] = maxpaths
        if (minpaths):
            path_parameters['min_paths'] = minpaths
        if(pathsperinitiator is not None):
            path_parameters['paths_per_initiator'] = pathsperinitiator

        parms['path_parameters'] = path_parameters
        parms['volume_changes'] = volChanges

        o = self.send_json_request(exportgroup_uri, parms)
        return self.check_for_sync(o, sync, synctimeout)

    def _get_resource_lun_tuple(self, resources, resType, baseResUri,
                                tenantname, projectname, blockTypeName):
        '''
        function to validate input volumes/snapshots
        and return list of ids and luns
        input
            list of volumes/snapshots in the format name:lun
        '''

        copyEntries = []
        snapshotObject = Snapshot(self.__ipAddr, self.__port)
        volumeObject = Volume(self.__ipAddr, self.__port)
        for copy in resources:
            copyParam = []
            try:
                copyParam = copy.split(":")
            except Exception as e:
                raise SOSError(
                    SOSError.CMD_LINE_ERR,
                    "Please provide valid format volume: lun for parameter " +
                    resType)
            copy = dict()
            if(not len(copyParam)):
                raise SOSError(
                    SOSError.CMD_LINE_ERR,
                    "Please provide atleast volume for parameter " + resType)
            if(resType == "volumes"):
                fullvolname = tenantname + "/" + projectname + "/"
                fullvolname += copyParam[0]
                copy['id'] = volumeObject.volume_query(fullvolname)
            if(resType == "snapshots"):
                copy['id'] = snapshotObject.snapshot_query(
                    'block', blockTypeName, baseResUri, copyParam[0])
            if(resType == "blockmirror"):
                copy['id'] = volumeObject.mirror_volume_query(
                    baseResUri, copyParam[0])
            if(len(copyParam) > 1):
                copy['lun'] = copyParam[1]
            copyEntries.append(copy)
        return copyEntries
