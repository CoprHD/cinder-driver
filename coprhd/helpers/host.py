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

import json

from oslo_log import log as logging
from cinder.i18n import _
from cinder.volume.drivers.coprhd.helpers import commoncoprhdapi as common
from cinder.volume.drivers.coprhd.helpers import tenant

LOG = logging.getLogger(__name__)


class Host(common.CoprHDResource):

    # All URIs for the Host operations
    URI_HOST_DETAILS = "/compute/hosts/{0}"
    URI_HOST_LIST_INITIATORS = "/compute/hosts/{0}/initiators"
    URI_COMPUTE_HOST = "/compute/hosts"
    URI_HOSTS_SEARCH_BY_NAME = "/compute/hosts/search?name={0}"
    URI_PAIRED_INITIATORS = "/compute/hosts/{0}/paired-initiators"
    URI_HOST_TAGS = "/compute/hosts/{0}/tags"
    URI_INITIATOR_TAGS = "/compute/initiators/{0}/tags"

    def query_by_name(self, host_name, tenant_name):
        """Search host matching host_name and tenant if tenant_name provided.
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

    def list_initiators(self, host_name, tenant):
        """Lists all initiators for the given host.

        :param host_name: The name of the host
        """
        if not common.is_uri(host_name):
            hostUri = self.query_by_name(host_name, tenant)
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

    def create(self, hostname, hosttype, label, tenant,
               usessl=False, osversion=None, autodiscovery=False,
               bootvolume=None, project=None, testconnection=None,
               isVirtual=False):
        """Takes care of creating a host system

        :param hostname: The short or fully qualified host name or IP address
                         of the host management interface.
        :param hosttype: The host OS type.
        :param label : The user label for this host.
        :param osversion : The operating system version of the host.
        :param tenant: The tenant name to which the host needs to be assigned
        :param use_ssl: One of {True, False}
        :param autodiscovery : Boolean value to indicate autodiscovery
                               true or false
        :param bootvolume : Name of the boot volume
        :param project: Project name
        :param testconnection: Whether or not to validate connection
        :param isVirtual: true if Host is a Virtual Machine

        """

        request = {'type': hosttype,
                   'name': label,
                   'host_name': hostname,
                   'discoverable': autodiscovery,
                   'use_ssl': usessl,
                   }

        tenantId = self.get_tenant_id(tenant)
        if(tenantId):
            request['tenant'] = tenantId

        if(osversion):
            request['os_version'] = osversion

        if(bootvolume and project):
            path = tenant + "/" + project + "/" + bootvolume
            volume_id = Volume(self.ipaddr, self.port).volume_query(path)
            request['boot_volume'] = volume_id

        if(isVirtual):
            request['virtual_machine'] = isVirtual

        host_create_uri = Host.URI_COMPUTE_HOST

        body = json.dumps(request)
        (s, h) = common.service_json_request(
            self.ipaddr, self.port,
            "POST",
            host_create_uri,
            body)
        o = common.json_decode(s)

        return o

    def search_by_name(self, host_name):
        """Search host by its name

        :param host_name: Host name
        :returns: Host details
        """
        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "GET",
            self.URI_HOSTS_SEARCH_BY_NAME.format(host_name), None)
        o = common.json_decode(s)
        if not o:
            return []
        return common.get_node_value(o, "resource")

    def create_paired_initiators_for_host(self,
                                          host_name,
                                          protocol,
                                          first_initiator_node,
                                          first_initiator_port,
                                          second_initiator_node,
                                          second_initiator_port,
                                          tenant):
        """Add initiator pairs to host

        :param host_name: Host name
        :param protocol: Protocol information
        :param first_initiator_node: First initiator node in the pair
        :param first_initiator_port: First initiator port in the pair
        :param second_initiator_node: Second initiator node in the pair
        :param second_initiator_port: Second initiator port in the pair
        """
        if not common.is_uri(host_name):
            hostUri = self.query_by_name(host_name, tenant)
        else:
            hostUri = host_name

        first_initiator = {'protocol': protocol,
                           'initiator_node': first_initiator_node,
                           'initiator_port': first_initiator_port
                           }
        second_initiator = {'protocol': protocol,
                            'initiator_node': second_initiator_node,
                            'initiator_port': second_initiator_port
                            }
        request = {'first_initiator': first_initiator,
                   'second_initiator': second_initiator
                   }

        body = json.dumps(request)

        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "POST",
            Host.URI_PAIRED_INITIATORS.format(hostUri),
            body)
        o = common.json_decode(s)
        return o

    def query_initiator_by_name(self, initiatorName, hostName, tenant):
        """Returns the initiator URI for matching the name of the initiator

        :param initiatorName: Name of the Initiator
        :param hostName: Host name
        :returns: Matching initiator's uri
        """

        hostUri = self.query_by_name(hostName, tenant)
        initiatorList = self.list_initiators(hostUri, tenant)
        # Match the name and return uri
        for initiator in initiatorList:
            if(initiator['name'] == initiatorName):
                return initiator['id']
        raise SOSError(
            SOSError.NOT_FOUND_ERR,
            "Initiator with name " +
            initiatorName +
            " not found")

    def get_tenant_id(self, tenantName):
        '''
         Fetch the tenant id
        '''
        tenantObj = tenant.Tenant(self.ipaddr, self.port)
        tenantId = tenantObj.get_tenant_by_name(tenantName)

        return tenantId
