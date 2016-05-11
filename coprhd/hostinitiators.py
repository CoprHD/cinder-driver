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

import json

from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import CoprHdError
from cinder.volume.drivers.emc.coprhd.host import Host

'''
The class definition for the operation on the CoprHD HostInitiator
'''


class HostInitiator(object):

    # All URIs for the Host Initiator operations
    URI_HOST_LIST_INITIATORS = "/compute/hosts/{0}/initiators"

    __hostObject = None

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the CoprHD instance. These
        are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port
        self.__hostObject = Host(self.__ipAddr, self.__port)

    """
    Initiator create operation
    """

    def create(self,
               sync,
               hostlabel,
               protocol,
               initiatorwwn,
               portwwn,
               initname,
               synctime,
               tenant):
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

                raise CoprHdError(
                    CoprHdError.SOS_FAILURE_ERR,
                    "error: task list is empty, no task response found")
        else:
            return result
