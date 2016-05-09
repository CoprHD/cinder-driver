#!/usr/bin/python

# Copyright (c) 2016 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.

from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError


class Cluster(object):

    '''
    The class definition for operations on 'Cluster'.
    '''
    URI_SERVICES_BASE = ''
    URI_TENANT = URI_SERVICES_BASE + '/tenant'
    URI_TENANTS = URI_SERVICES_BASE + '/tenants/{0}'
    URI_TENANTS_CLUSTERS = URI_TENANTS + '/clusters'

    URI_CLUSTERS = URI_SERVICES_BASE + '/compute/clusters'
    URI_CLUSTER = URI_SERVICES_BASE + '/compute/clusters/{0}'
    URI_CLUSTERS_BULKGET = URI_CLUSTERS + '/bulk'
    URI_CLUSTER_DETACH = URI_CLUSTER + '/detach-storage'

    URI_CLUSTER_SEARCH = URI_SERVICES_BASE + '/compute/clusters/search'
    URI_CLUSTER_SEARCH_NAME = URI_CLUSTER_SEARCH + '?name={0}'
    URI_CLUSTER_HOSTS = URI_CLUSTER + '/hosts'

    URI_RESOURCE_DEACTIVATE = '{0}/deactivate'

    URI_CLUSTER_LIST_UM_VOLUMES = URI_CLUSTER + "/unmanaged-volumes"
    URI_CLUSTER_LIST_UM_EXPORT_MASKS = URI_CLUSTER + "/unmanaged-export-masks"
    BOOL_TYPE_LIST = ['true', 'false']

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the SOS instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def cluster_show_uri(self, uri):
        (s, h) = common.service_json_request(self.__ipAddr, self.__port, "GET",
                                             Cluster.URI_CLUSTER.format(uri),
                                             None, None, False)
        o = common.json_decode(s)
        if(o['inactive'] is False):
            return o

        return None

        '''
        search cluster action
        Parameters:
            name : Name of the cluster
        Returns:
            return clusters list
        '''

    def cluster_search(self, name):

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port, "GET",
            Cluster.URI_CLUSTER_SEARCH_NAME.format(name), None)
        o = common.json_decode(s)
        return o['resource']

        '''
        query cluster action
        Parameters:
            name : Name of the cluster
            tenant : name of tenant
        Returns:
            return cluster id or uri
        '''
    # default = None(provider tenant)

    def cluster_query(self, name, tenant=None):

        resources = self.cluster_search(name)
        for resource in resources:
            details = self.cluster_show_uri(resource['id'])
            if (details is not None and details['name'] == name):
                return resource['id']

        raise SOSError(SOSError.NOT_FOUND_ERR,
                       "cluster " + name + ": not found")
