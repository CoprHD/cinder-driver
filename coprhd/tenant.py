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


from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import CoprHdError


class Tenant(object):

    '''
    The class definition for operations on 'Tenant'.
    '''

    URI_SERVICES_BASE = ''
    URI_TENANT = URI_SERVICES_BASE + '/tenant'
    URI_TENANTS = URI_SERVICES_BASE + '/tenants/{0}'
    URI_TENANTS_SUBTENANT = URI_TENANTS + '/subtenants'

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the CoprHD instance. These
        are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def tenant_query(self, label):
        '''
        Returns the UID of the tenant specified by the hierarchical name
        (ex tenant1/tenant2/tenant3)
        '''

        if (common.is_uri(label)):
            return label

        tenant_id = self.tenant_getid()

        if not label:
            return tenant_id

        subtenants = self.tenant_list(tenant_id)
        subtenants.append(self.tenant_show(None))

        for tenant in subtenants:
            if (tenant['name'] == label):
                rslt = self.tenant_show_by_uri(tenant['id'])
                if(rslt):
                    return tenant['id']

        raise CoprHdError(CoprHdError.NOT_FOUND_ERR,
                          "Tenant " + label + ": not found")

    def tenant_show(self, label, xml=False):
        '''
        Returns the details of the tenant based on its name
        '''
        if label:
            tenant_id = self.tenant_query(label)
        else:
            tenant_id = self.tenant_getid()

        return self.tenant_show_by_uri(tenant_id, xml)

    def tenant_getid(self):
        (s, h) = common.service_json_request(self.__ipAddr, self.__port,
                                             "GET", Tenant.URI_TENANT, None)

        o = common.json_decode(s)
        return o['id']

    def tenant_list(self, uri=None):
        '''
        Returns all the tenants under a parent tenant
        Parameters:
            parent: The parent tenant name
        Returns:
                JSON payload of tenant list
        '''

        if (not uri):
            uri = self.tenant_getid()

        tenantdtls = self.tenant_show_by_uri(uri, False)

        if(tenantdtls and not ('parent_tenant' in tenantdtls and
                               ("id" in tenantdtls['parent_tenant']))):
            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port,
                "GET", self.URI_TENANTS_SUBTENANT.format(uri), None)

            o = common.json_decode(s)
            return o['subtenant']

        else:
            return []

    def tenant_show_by_uri(self, uri, xml=False):
        '''
        Makes a REST API call to retrieve details of a tenant based on its UUID
        '''
        (s, h) = common.service_json_request(self.__ipAddr, self.__port, "GET",
                                             Tenant.URI_TENANTS.format(uri),
                                             None, None, xml)

        if(not xml):
            o = common.json_decode(s)
            if('inactive' in o):
                if(o['inactive']):
                    return None
        else:
            return s

        return o

    def get_tenant_by_name(self, tenant):
        uri = None
        if (not tenant):
            uri = self.tenant_getid()
        else:
            if not common.is_uri(tenant):
                uri = self.tenant_query(tenant)
            else:
                uri = tenant
            if (not uri):
                raise CoprHdError(CoprHdError.NOT_FOUND_ERR,
                                  'Tenant ' + tenant + ': not found')
        return uri
