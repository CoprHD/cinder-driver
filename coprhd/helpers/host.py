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

from cinder.i18n import _
from cinder.volume.drivers.coprhd.helpers import commoncoprhdapi as common
from cinder.volume.drivers.coprhd.helpers import tenant


class Host(common.CoprHDResource):

    # All URIs for the Host operations
    URI_HOST_DETAILS = "/compute/hosts/{0}"
    URI_HOST_LIST_INITIATORS = "/compute/hosts/{0}/initiators"
    URI_COMPUTE_HOST = "/compute/hosts"
    URI_SEARCH_HOSTS_BY_TAG = "/compute/hosts/search?tag={0}"
    URI_HOST_DEACTIVATE = URI_HOST_DETAILS + '/deactivate?detach_storage=true'
    URI_SEARCH_INITIATORS_BY_TAG = '/compute/initiators/search?tag={0}'
    URI_INITIATOR_DEACTIVATE = '/compute/initiators/{0}/deactivate'

    def query_by_name(self, host_name, tenant_name=None):
        """Search host matching host_name and tenant if tenant_name provided.

        tenant_name is optional
        """
        hostList = self.list_all(tenant_name)
        for host in hostList:
            hostUri = host['id']
            hostDetails = self.show_by_uri(hostUri)
            if hostDetails:
                if hostDetails['name'] == host_name:
                    return hostUri

        raise common.CoprHdError(common.CoprHdError.NOT_FOUND_ERR, (_(
                                 "Host with name: %s not found") % host_name))

    def list_initiators(self, host_name):
        """Lists all initiators for the given host.

        :param host_name: The name of the host
        """
        if not common.is_uri(host_name):
            hostUri = self.query_by_name(host_name, None)
        else:
            hostUri = host_name

        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "GET",
            Host.URI_HOST_LIST_INITIATORS.format(hostUri),
            None)
        o = common.json_decode(s)

        if not o or "initiator" not in o:
            return []

        return common.get_node_value(o, 'initiator')

    def list_all(self, tenant_name):
        """Gets the ids and self links for all compute elements."""
        restapi = self.URI_COMPUTE_HOST
        tenant_obj = tenant.Tenant(self.ipaddr, self.port)
        if tenant_name is None:
            tenant_uri = tenant_obj.tenant_getid()
        else:
            tenant_uri = tenant_obj.tenant_query(tenant_name)
        restapi = restapi + "?tenant=" + tenant_uri

        (s, h) = common.service_json_request(
            self.ipaddr, self.port,
            "GET",
            restapi,
            None)
        o = common.json_decode(s)
        return o['host']

    def show_by_uri(self, uri):
        """Makes REST API call to retrieve Host details based on its UUID."""
        (s, h) = common.service_json_request(self.ipaddr, self.port, "GET",
                                             Host.URI_HOST_DETAILS.format(uri),
                                             None)
        o = common.json_decode(s)
        inactive = common.get_node_value(o, 'inactive')

        if inactive:
            return None
        return o

    def delete_host(self, host_uri, detach_storage=True):
        '''
        Makes a REST API call to delete a host by its UUID
        '''

        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "POST",
            Host.URI_HOST_DEACTIVATE.format(host_uri),
            None)

        return

    def delete_initiator(self, initiator_uri):
        '''
        Makes a REST API call to delete an initiator by its UUID
        '''
        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "POST",
            Host.URI_INITIATOR_DEACTIVATE.format(initiator_uri),
            None)

        return
