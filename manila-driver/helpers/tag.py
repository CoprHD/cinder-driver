#!/usr/bin/python

# Copyright (c) 2012 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
'''
Contains tagging related methods
'''


import oslo_serialization

from manila.share.drivers.coprhd.helpers import common as commoncoprhdapi
from manila.share.drivers.coprhd.helpers.common import SOSError
import json


from manila.i18n import _
from manila.share.drivers.coprhd.helpers import common as common


class Tag(common.CoprHDResource):

    def tag_resource(self, uri, resource_id, add, remove):
        params = {
            'add': add,
            'remove': remove
        }

        body = oslo_serialization.jsonutils.dumps(params)

        (s, h) = common.service_json_request(self.ipaddr, self.port, "PUT",
                                             uri.format(resource_id), body)
        o = common.json_decode(s)
        return o
    



def add_tag_parameters(parser_object):
    parser_object.add_argument('-add',
                               help='Tags to be added',
                               dest='add',
                               nargs="+",
                               metavar='<addtags>')

    parser_object.add_argument('-remove',
                               help='Tags to be removed',
                               dest='remove',
                               nargs="+",
                               metavar='<removetags>')


def add_mandatory_project_parameter(mandatory_args):
    mandatory_args.add_argument('-project', '-pr',
                                metavar='<projectname>',
                                dest='project',
                                help='Name of project',
                                required=True)


def tag_resource(ipaddr, port, uri, resourceid, add, remove):

        params = {
            'add': add,
            'remove': remove
        }
        body = json.dumps(params)

        (s, h) = commoncoprhdapi.service_json_request(ipaddr, port, "PUT",
                                             uri.format(resourceid), body)
        o = commoncoprhdapi.json_decode(s)
        return o


def list_tags(ipaddr, port, resourceUri):

    if(resourceUri.__contains__("tag") is False):
        raise SOSError(SOSError.VALUE_ERR, "URI should end with /tag")

    (s, h) = commoncoprhdapi.service_json_request(ipaddr,
                                         port,
                                         "GET",
                                         resourceUri,
                                         None)
    allTags = []
    try:
        o = commoncoprhdapi.json_decode(s)
        allTags = o['tag']
    except SOSError as e:
        raise e

    return allTags
