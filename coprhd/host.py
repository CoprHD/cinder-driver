#!/usr/bin/python

#
# Copyright (c) 2016 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
#

from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
import json
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError
from cinder.volume.drivers.emc.coprhd.tenant import Tenant
from cinder.volume.drivers.emc.coprhd.volume import Volume

'''
The class definition for the operation on the ViPR Host
'''


class Host(object):
    # Indentation START for the class

    # All URIs for the Host operations
    URI_HOST_DETAILS = "/compute/hosts/{0}"
    URI_HOST_DEACTIVATE = "/compute/hosts/{0}/deactivate"
    URI_HOST_DETACH_STORAGE = "/compute/hosts/{0}/detach-storage"
    URI_HOST_LIST_INITIATORS = "/compute/hosts/{0}/initiators"
    URI_HOST_LIST_IPINTERFACES = "/compute/hosts/{0}/ip-interfaces"
    URI_HOST_DISCOVER = URI_HOST_DETAILS + "/discover"
    URI_COMPUTE_HOST = "/compute/hosts"
    URI_COMPUTE_HOST_PROV_BARE_METEL = \
        URI_COMPUTE_HOST + "/provision-bare-metal"
    URI_COMPUTE_HOST_OS_INSTALL = URI_COMPUTE_HOST + "/{0}/os-install"
    URI_HOSTS_SEARCH_BY_NAME = "/compute/hosts/search?name={0}"
    URI_HOST_LIST_UM_EXPORT_MASKS = "/compute/hosts/{0}/unmanaged-export-masks"
    URI_HOST_LIST_UM_VOLUMES = "/compute/hosts/{0}/unmanaged-volumes"

    HOST_TYPE_LIST = ['Windows', 'HPUX', 'Linux',
                      'Esx', 'Other', 'AIXVIO', 'AIX', 'No_OS', 'SUNVCS']

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    '''
    Host creation operation
    '''

    def create(self, hostname, hosttype, label, tenant, port,
               username, passwd, usessl, osversion, cluster,
               datacenter, vcenter, autodiscovery,
               bootvolume, project, testconnection):
        '''
        Takes care of creating a host system.
        Parameters:
            hostname: The short or fully qualified host name or IP address
                of the host management interface.
            hosttype : The host type.
            label : The user label for this host.
            osversion : The operating system version of the host.
            port: The integer port number of the host management interface.
            username: The user credential used to login to the host.
            passwd: The password credential used to login to the host.
            tenant: The tenant name to which the host needs to be assigned
            cluster: The id of the cluster if the host is in a cluster.
            use_ssl: One of {True, False}
            datacenter: The id of a vcenter data center if the host is an
                ESX host in a data center.
            autodiscovery : Boolean value to indicate autodiscovery
                true or false
        Returns:
            Response payload
        '''

        request = {'type': hosttype,
                   'name': label,
                   'host_name': hostname,
                   'port_number': port,
                   'user_name': username,
                   'password': passwd,
                   'discoverable': autodiscovery,
                   'use_ssl': usessl
                   }

        '''
        check if the host is already present in this tenant
        '''
        tenantId = self.get_tenant_id(tenant)
        if(tenantId):
            request['tenant'] = tenantId

        if(osversion):
            request['os_version'] = osversion

        if(cluster):
            request['cluster'] = self.get_cluster_id(cluster, tenant)

        if(datacenter):
            request['vcenter_data_center'] = self.get_vcenterdatacenter_id(
                datacenter, vcenter, tenant)

        if(bootvolume and project):
            path = tenant + "/" + project + "/" + bootvolume
            volume_id = Volume(self.__ipAddr, self.__port).volume_query(path)
            request['boot_volume'] = volume_id

        restapi = Host.URI_COMPUTE_HOST
        if(testconnection):
            restapi = restapi + "?validate_connection=true"

        body = json.dumps(request)
        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "POST",
            restapi,
            body)
        o = common.json_decode(s)

        return o


    '''
    Search the host matching the hostName and
    tenant if tenantName is provided. tenantName is optional
    '''

    def query_by_name(self, hostName, tenant=None):
        hostList = self.list_all(tenant)
        for host in hostList:
            hostUri = host['id']
            hostDetails = self.show_by_uri(hostUri)
            if(hostDetails):
                if(hostDetails['name'] == hostName):
                    return hostUri

        raise SOSError(SOSError.NOT_FOUND_ERR,
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

    def show_by_uri(self, uri, xml=False):
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
        if(xml):
            (s, h) = common.service_json_request(
                self.__ipAddr, self.__port, "GET",
                Host.URI_HOST_DETAILS.format(uri),
                None, None, xml)
            return s
        else:
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
