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
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError
import json


class VirtualPool(object):

    '''
    The class definition for operations on 'Class of Service'.
    '''

    URI_VPOOL = "/{0}/vpools"
    URI_VPOOL_BY_VDC_ID = "/{0}/vpools?vdc-id={1}"
    URI_VPOOL_SHOW = URI_VPOOL + "/{1}"
    URI_VPOOL_STORAGEPOOL = URI_VPOOL_SHOW + "/storage-pools"
    URI_VPOOL_ACL = URI_VPOOL_SHOW + "/acl"
    URI_TENANT = '/tenants/{0}'
    URI_VPOOL_DEACTIVATE = URI_VPOOL_SHOW + '/deactivate'
    URI_VPOOL_REFRESH_POOLS = URI_VPOOL_SHOW + "/refresh-matched-pools"
    URI_VPOOL_ASSIGN_POOLS = URI_VPOOL_SHOW + "/assign-matched-pools"
    URI_VPOOL_SEARCH = URI_VPOOL + "/search?name={1}"
    URI_OBJECT_VPOOL = '/object/vpools'

    PROTOCOL_TYPE_LIST = ['FC', 'iSCSI', 'NFS', 'CIFS', 'S3', 'Atmos', 'Swift']
    RAID_LEVEL_LIST = ['RAID1', 'RAID2', 'RAID3', 'RAID4',
                       'RAID5', 'RAID6', 'RAID10']
    BOOL_TYPE_LIST = ['true', 'false']
    DRIVE_TYPE_LIST = ['SSD', 'FC', 'SAS', 'NL_SAS', 'SATA', 'HARD_DISK_DRIVE']
    RPO_UNITS = ['SECONDS', 'MINUTES', 'HOURS', 'WRITES',
                 'BYTES', 'KB', 'MB', 'GB', 'TB']

    ALREADY_EXISTS_STR = 'label {0} already exists'

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def vpool_show_uri(self, vpooltype, uri, xml=False):
        '''
        This function will take uri as input and returns with
        all parameters of VPOOL like label, urn and type.
        parameters
            uri : unique resource identifier.
        return
            returns with object contain all details of VPOOL.
        '''
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            self.URI_VPOOL_SHOW.format(vpooltype, uri), None, None)

        o = common.json_decode(s)
        if(o['inactive']):
            return None

        if(xml is False):
            return o

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            self.URI_VPOOL_SHOW.format(vpooltype, uri), None, None, xml)
        return s

    def vpool_query(self, name, vpooltype):
        '''
        This function will take the VPOOL name and type of VPOOL
        as input and get uri of the first occurance of given VPOOL.
        parameters:
             name : Name of the VPOOL.
             vpooltype : Type of the VPOOL {'block' }
        return
            return with uri of the given vpool.
        '''
        if (common.is_uri(name)):
            return name

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            self.URI_VPOOL_SEARCH.format(vpooltype, name), None)

        o = common.json_decode(s)
        if(len(o['resource']) > 0):
            # Get the Active vpool ID.
            for vpool in o['resource']:
                if self.vpool_show_uri(vpooltype, vpool['id'], False) is not None:
                    return vpool['id']
        # Riase not found exception. as we did not find any active vpool.
        raise SOSError(SOSError.NOT_FOUND_ERR, "VPool " + name +
                       " (" + vpooltype + ") " + ": not found")
