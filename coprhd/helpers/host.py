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
from cinder.volume.drivers.emc.coprhd.helpers.tenant import Tenant

'''
The class definition for the operation on the CoprHD Host
'''


class Host(object):

    # All URIs for the Host operations
    URI_HOST_DETAILS = "/compute/hosts/{0}"
    URI_HOST_LIST_INITIATORS = "/compute/hosts/{0}/initiators"
    URI_COMPUTE_HOST = "/compute/hosts"
    URI_HOSTS_SEARCH_BY_NAME = "/compute/hosts/search?name={0}"

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the CoprHD instance. These
        are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    '''
    Search the host matching the hostName and
    tenant if tenantName is provided. tenantName is optional
    '''

    def query_by_name(self, hostName, tenant=None):
        hostList = self.list_all(tenant)
        for host in hostList:
            hostUri = host['id']
            hostDetails = self.show_by_uri(hostUri)
            if hostDetails:
                if hostDetails['name'] == hostName:
                    return hostUri

        raise CoprHdError(CoprHdError.NOT_FOUND_ERR,
                          "Host with name '" + hostName + "' not found")

    '''
    Gets the list of Initiators belonging to a given Host
    '''

    def list_initiators(self, hostName):
        '''
         Lists all initiators for the given host
         Parameters
             hostName : The name of the host
        '''
        if(not common.is_uri(hostName)):
            hostUri = self.query_by_name(hostName, None)
        else:
            hostUri = hostName

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            Host.URI_HOST_LIST_INITIATORS.format(hostUri),
            None)
        o = common.json_decode(s)

        if(not o or "initiator" not in o):
            return []

        return common.get_node_value(o, 'initiator')

    '''
    Gets the ids and self links for all compute elements.
    '''

    def list_all(self, tenant):
        restapi = self.URI_COMPUTE_HOST
        tenant_obj = Tenant(self.__ipAddr, self.__port)
        if(tenant is None):
            tenant_uri = tenant_obj.tenant_getid()
        else:
            tenant_uri = tenant_obj.tenant_query(tenant)
        restapi = restapi + "?tenant=" + tenant_uri

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "GET",
            restapi,
            None)
        o = common.json_decode(s)
        return o['host']

    '''
    Gets the host system details, given its uri/id
    '''

    def show_by_uri(self, uri):
        '''
        Makes a REST API call to retrieve details of a Host based on its UUID
        '''
        (s, h) = common.service_json_request(self.__ipAddr, self.__port, "GET",
                                             Host.URI_HOST_DETAILS.format(uri),
                                             None, None)
        o = common.json_decode(s)
        inactive = common.get_node_value(o, 'inactive')

        if(inactive):
            return None
        return o

    def search_by_name(self, host_name):
        '''
        Search host by its name
        '''
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            self.URI_HOSTS_SEARCH_BY_NAME.format(host_name), None)
        o = common.json_decode(s)
        if not o:
            return []
        return common.get_node_value(o, "resource")
