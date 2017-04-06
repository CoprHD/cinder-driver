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

LOG = logging.getLogger(__name__)


class Network(common.CoprHDResource):

    # All URIs for Network Operations
    URI_NETWORK_SEARCH = "/vdc/networks?wwn={0}"
    URI_NETWORK_ENDPOINTS = '/vdc/networks/{0}/endpoints/'

    def query_by_initiator(self, initiator):
        """Returns the URIs of networks based on initiator.

        :param initiator: The initiator to be searched in the network.
        :returns The URIs of the networks where the initiator is found.
        """

        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "GET",
            self.URI_NETWORK_SEARCH.format(initiator), None)

        o = common.json_decode(s)

        return o['network'][0]['id']

    def add_endpoint(self, network_uri, endpoint):
        """Adds an endpoint to the network.

        :param network_uri: The URI of the network.
        :param endpoint: This is the initiator to be added.
        """

        body = json.dumps({'endpoints': [endpoint],
                           'op': 'add'})

        (s, h) = common.service_json_request(
            self.ipaddr, self.port,
            "PUT", Network.URI_NETWORK_ENDPOINTS.format(network_uri),
            body)

        o = common.json_decode(s)

        return o
