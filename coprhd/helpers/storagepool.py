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

class StoragePool(common.CoprHDResource):

    # All URIs for StoragePool Operations
    URI_STORAGE_POOL_SHOW = "/vdc/storage-pools/{0}"

    def storagepool_list_by_uri(self, uri):
        """Returns the URIs of networks based on initiator.

        :param initiator: The initiator to be searched in the network.
        :returns The URIs of the networks where the initiator is found.
        """

        (s, h) = common.service_json_request(
            self.ipaddr, self.port, "GET",
            self.URI_STORAGE_POOL_SHOW.format(uri), None)

        o = common.json_decode(s)

        return o    