#!/usr/bin/python
# Copyright (c)2016 EMC Corporation
# All Rights Reserved

# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.

import json
from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError


class VirtualArray(object):

    '''
    The class definition for operations on 'VirtualArray'.
    '''

    # Commonly used URIs for the 'varrays' module
    URI_VIRTUALARRAY = '/vdc/varrays'
    URI_VIRTUALARRAY_BY_VDC_ID = '/vdc/varrays?vdc-id={0}'
    URI_VIRTUALARRAY_URI = '/vdc/varrays/{0}'
    URI_VIRTUALARRAY_ACLS = URI_VIRTUALARRAY_URI + '/acl'
    URI_RESOURCE_DEACTIVATE = '{0}/deactivate'
    URI_AUTO_TIER_POLICY = "/vdc/varrays/{0}/auto-tier-policies"
    URI_LIST_STORAGE_PORTS = "/vdc/varrays/{0}/storage-ports"
    URI_STORAGE_PORT_DETAILS = "/vdc/storage-ports/{0}"

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance.
        These are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def varray_query(self, name):
        '''
        Returns the UID of the varray specified by the name
        '''
        if (common.is_uri(name)):
            return name

        uris = self.varray_list()

        for uri in uris:
            varray = self.varray_show(uri, False)
            if(varray):
                if(varray['name'] == name):
                    return varray['id']

        raise SOSError(SOSError.NOT_FOUND_ERR,
                       "varray " + name + ": not found")

    def varray_list(self, vdcname=None):
        '''
        Returns all the varrays in a vdc
        Parameters:
        Returns:
                JSON payload of varray list
        '''
        vdcuri = None
        vdcrestapi = None
        if(vdcname != None):
            vdcrestapi = VirtualArray.URI_VIRTUALARRAY_BY_VDC_ID.format(
                vdcname)
        else:
            vdcrestapi = VirtualArray.URI_VIRTUALARRAY
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            vdcrestapi, None)

        o = common.json_decode(s)

        returnlst = []
        for item in o['varray']:
            returnlst.append(item['id'])

        return returnlst

    def varray_show(self, label, xml=False):
        '''
        Makes a REST API call to retrieve details of a varray
        based on its UUID
        '''
        uri = self.varray_query(label)

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            VirtualArray.URI_VIRTUALARRAY_URI.format(uri),
            None, None, xml)

        if(xml is False):
            o = common.json_decode(s)
            if('inactive' in o):
                if(o['inactive'] is True):
                    return None
                else:
                    return o
        else:
            return s
