#!/usr/bin/python

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


from cinder.volume.drivers.emc.coprhd.helpers import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.helpers.commoncoprhdapi \
    import CoprHdError


class VirtualArray(object):

    '''
    The class definition for operations on 'VirtualArray'.
    '''

    # Commonly used URIs for the 'varrays' module
    URI_VIRTUALARRAY = '/vdc/varrays'
    URI_VIRTUALARRAY_BY_VDC_ID = '/vdc/varrays?vdc-id={0}'
    URI_VIRTUALARRAY_URI = '/vdc/varrays/{0}'

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the CoprHD instance.
        These are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def varray_query(self, name):
        '''
        Returns the UID of the varray specified by the name
        '''
        if common.is_uri(name):
            return name

        uris = self.varray_list()

        for uri in uris:
            varray = self.varray_show(uri, False)
            if varray and varray['name'] == name:
                    return varray['id']

        raise CoprHdError(CoprHdError.NOT_FOUND_ERR,
                          "varray " + name + ": not found")

    def varray_list(self, vdcname=None):
        '''
        Returns all the varrays in a vdc
        Parameters:
        Returns:
                JSON payload of varray list
        '''
        vdcrestapi = None
        if vdcname is not None:
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

    def varray_show(self, label):
        '''
        Makes a REST API call to retrieve details of a varray
        based on its UUID
        '''
        uri = self.varray_query(label)

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            VirtualArray.URI_VIRTUALARRAY_URI.format(uri),
            None, None)

        o = common.json_decode(s)
        if 'inactive' in o and o['inactive'] is True:
            return None
        else:
            return o
