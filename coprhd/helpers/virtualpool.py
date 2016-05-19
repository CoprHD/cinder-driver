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


class VirtualPool(object):

    URI_VPOOL = "/{0}/vpools"
    URI_VPOOL_SHOW = URI_VPOOL + "/{1}"
    URI_VPOOL_SEARCH = URI_VPOOL + "/search?name={1}"

    def __init__(self, ipAddr, port):
        '''Constructor: takes IP address and port of the CoprHD instance.

        These are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def vpool_show_uri(self, vpooltype, uri):
        '''Makes REST API call and retrieves vpool details based on UUID

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
            self.URI_VPOOL_SHOW.format(vpooltype, uri), None)

        o = common.json_decode(s)
        if o['inactive']:
            return None

        return o

    def vpool_query(self, name, vpooltype):
        '''Makes REST API call to query the vpool by name and type

        This function will take the VPOOL name and type of VPOOL
        as input and get uri of the first occurance of given VPOOL.
        parameters:
             name : Name of the VPOOL.
             vpooltype : Type of the VPOOL {'block' }
        return
            return with uri of the given vpool.
        '''
        if common.is_uri(name):
            return name

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            self.URI_VPOOL_SEARCH.format(vpooltype, name), None)

        o = common.json_decode(s)
        if len(o['resource']) > 0:
            # Get the Active vpool ID.
            for vpool in o['resource']:
                if self.vpool_show_uri(vpooltype, vpool['id']) is not None:
                    return vpool['id']
        # Raise not found exception. as we did not find any active vpool.
        raise CoprHdError(CoprHdError.NOT_FOUND_ERR, "VPool " + name +
                          " (" + vpooltype + ") " + ": not found")
