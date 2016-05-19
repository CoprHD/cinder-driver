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


'''
Contains tagging related methods
'''

import oslo_serialization

from cinder.volume.drivers.emc.coprhd.helpers import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.helpers.commoncoprhdapi \
    import CoprHdError


def tag_resource(ipaddr, port, uri, resourceid, add, remove):

    params = {
        'add': add,
        'remove': remove
    }
    body = oslo_serialization.jsonutils.dumps(params)

    (s, h) = common.service_json_request(ipaddr, port, "PUT",
                                         uri.format(resourceid), body)
    o = common.json_decode(s)
    return o


def list_tags(ipaddr, port, resourceUri):

    if resourceUri.__contains__("tag") is False:
        raise CoprHdError(CoprHdError.VALUE_ERR, "URI should end with /tag")

    (s, h) = common.service_json_request(ipaddr,
                                         port,
                                         "GET",
                                         resourceUri,
                                         None)
    allTags = []
    try:
        o = common.json_decode(s)
        allTags = o['tag']
    except CoprHdError as e:
        raise e

    return allTags
