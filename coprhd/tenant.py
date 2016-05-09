#!/usr/bin/python
# Copyright (c) 2016 EMC Corporation
# All Rights Reserved

# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.

#from cli.src import common
from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
import json
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError


class Tenant(object):

    '''
    The class definition for operations on 'Tenant'.
    '''

    URI_SERVICES_BASE = ''
    URI_TENANT = URI_SERVICES_BASE + '/tenant'
    URI_TENANTS = URI_SERVICES_BASE + '/tenants/{0}'
    URI_TENANTS_SUBTENANT = URI_TENANTS + '/subtenants'
    URI_TENANT_CONTENT = URI_TENANT
    URI_TENANT_ROLES = URI_TENANTS + '/role-assignments'
    URI_SUBTENANT = URI_TENANT + '/subtenants'
    URI_SUBTENANT_INFO = URI_SUBTENANT + '/{0}'
    URI_RESOURCE_DEACTIVATE = '{0}/deactivate'
    URI_TENANT_HOSTS = URI_TENANTS + '/hosts'
    URI_TENANT_CLUSTERS = URI_TENANTS + '/clusters'
    URI_TENANT_VCENTERS = URI_TENANTS + '/vcenters'

    URI_NAMESPACE_COMMON = URI_SERVICES_BASE + '/object/namespaces'
    URI_NAMESPACE_BASE = URI_NAMESPACE_COMMON + '/namespace'
    URI_NAMESPACE_INSTANCE = URI_NAMESPACE_BASE + '/{0}'
    URI_NAMESPACE_TENANT_BASE = URI_NAMESPACE_COMMON + '/tenant'
    URI_NAMESPACE_TENANT_INSTANCE = URI_NAMESPACE_TENANT_BASE + '/{0}'

    URI_LIST_NAMESPACES = '/vdc/object-namespaces'
    URI_NAMESPACE_SHOW = '/vdc/object-namespaces/{0}'

    # New APIs for listing namespaces associated with a storagesystem

    URI_LIST_SS = "/vdc/storage-systems/{0}/object-namespaces"
    URI_LIST_SS_NAMESPACE = "/vdc/storage-systems/{0}/object-namespaces/{1}"

    PROVIDER_TENANT = "Provider Tenant"
    TENANT_ROLES = ['TENANT_ADMIN', 'PROJECT_ADMIN', 'TENANT_APPROVER']

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
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

        id = self.tenant_getid()

        if not label:
            return id

        subtenants = self.tenant_list(id)
        subtenants.append(self.tenant_show(None))

        for tenant in subtenants:
            if (tenant['name'] == label):
                rslt = self.tenant_show_by_uri(tenant['id'])
                if(rslt):
                    return tenant['id']

        raise SOSError(SOSError.NOT_FOUND_ERR,
                       "Tenant " + label + ": not found")

    def tenant_show(self, label, xml=False):
        '''
        Returns the details of the tenant based on its name
        '''
        if label:
            id = self.tenant_query(label)
        else:
            id = self.tenant_getid()

        return self.tenant_show_by_uri(id, xml)

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

        if(tenantdtls and not ('parent_tenant' in tenantdtls
                               and ("id" in tenantdtls['parent_tenant']))):
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
                raise SOSError(SOSError.NOT_FOUND_ERR,
                               'Tenant ' + tenant + ': not found')
        return uri
