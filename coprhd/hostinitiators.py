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
from cinder.volume.drivers.emc.coprhd.host import Host
import sys

'''
The class definition for the operation on the ViPR HostInitiator
'''


class HostInitiator(object):
    # Indentation START for the class

    '''
    /compute/initiators/search
    /compute/initiators/{id}
    /compute/initiators/{id}/deactivate
    /compute/initiators/{id}/exports
    '''
    # All URIs for the Host Initiator operations
    URI_INITIATOR_DETAILS = "/compute/initiators/{0}"
    URI_INITIATOR_DETAILS_BULK = "/compute/initiators/bulk"
    URI_HOST_LIST_INITIATORS = "/compute/hosts/{0}/initiators"
    URI_INITIATOR_DEACTIVATE = "/compute/initiators/{0}/deactivate"

    INITIATOR_PROTOCOL_LIST = ['FC', 'iSCSI']

    __hostObject = None

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance. These are
        needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port
        self.__hostObject = Host(self.__ipAddr, self.__port)

    """
    Initiator create operation
    """

    def create(self, sync, hostlabel, protocol, initiatorwwn, portwwn, initname, synctime, tenant):
        hostUri = self.get_host_uri(hostlabel, tenant)
        request = {'protocol': protocol,
                   'initiator_port': portwwn,
                   'name': initname
                   }

        if(initiatorwwn):
            request['initiator_node'] = initiatorwwn

        body = json.dumps(request)

        (s, h) = common.service_json_request(
            self.__ipAddr, self.__port,
            "POST",
            HostInitiator.URI_HOST_LIST_INITIATORS.format(hostUri),
            body)
        o = common.json_decode(s)
        return self.check_for_sync(o, sync, synctime)

    '''
    Given the name of the host, returns the hostUri/id
    '''

    def get_host_uri(self, hostName, tenant=None):
        return self.__hostObject.query_by_name(hostName, tenant)

    def check_for_sync(self, result, sync, synctime):
        if(sync):
            if(len(result["resource"]) > 0):
                resource = result["resource"]

                return (
                    common.block_until_complete("initiator", resource["id"],
                                                result["id"], self.__ipAddr,
                                                self.__port, synctime)


                )
            else:

                raise SOSError(
                    SOSError.SOS_FAILURE_ERR,
                    "error: task list is empty, no task response found")
        else:
            return result
