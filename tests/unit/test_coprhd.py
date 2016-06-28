
# Copyright (c) 2012 - 2014 EMC Corporation, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from cinder import context
#from cinder.openstack.common import log as logging
from cinder import test
from cinder.volume import volume_types
from mock import MagicMock
from mock import Mock
from mock import patch

#LOG = logging.getLogger(__name__)

'''
Test Data required for mocking
'''
export_group_details_data = {
    "inactive": False,
    "initiators": [{"creation_time": 1392194176020,
                    "host": {"id": "urn:storageos:Host:3e21edff-8662-4e60-ab5",
                             "link": {"href": "/compute/hosts/urn:storageos:H",
                                      "rel": "self"}},
                    "hostname": "lglw7134",
                    "id": "urn:storageos:Initiator:13945431-06b7-44a0-838c-50",
                    "inactive": False,
                    "initiator_node": "20:00:00:90:FA:13:81:8D",
                    "initiator_port": "iqn.1993-08.org.deb:01:222",
                    "link": {"href": "/compute/initiators/urn:storageos:Initi",
                             "rel": "self"},
                    "protocol": "iSCSI",
                    "registration_status": "REGISTERED",
                    "tags": []}],
    "name": "ccgroup",
    "project": 'project',
    "tags": [],
    "tenant": 'tenant',
    "type": "Host",
    "varray": {"id": "urn:storageos:VirtualArray:5af376e9-ce2f-493d-9079-a872",
               "link": {"href": "/vdc/varrays/urn:storageos:VirtualArray:5af3",
                        "rel": "self"}
               }}

varray_detail_data = {"name": "varray"}

export_group_list = ["urn:storageos:ExportGroup:2dbce233-7da0-47cb-8ff3-68f48"]

iscsi_itl_list = {"itl": [{"hlu": 3,
                           "initiator": {"id": "urn:storageos:Initiator:13945",
                                         "link": {"rel": "self",
                                                  "href": "/comput"},
                                         "port": "iqn.1993-08.org.deb:01:222"},
                           "export": {"id": "urn:storageos:ExportGroup:2dbce2",
                                      "name": "ccgroup",
                                      "link": {"rel": "self",
                                               "href": "/block/expo"}},
                           "device": {"id": "urn:storageos:Volume:aa1fc84a-af",
                                      "link": {"rel": "self",
                                               "href": "/block/volumes/urn:s"},
                                      "wwn": "600009700001957015735330303535"},
                           "target": {"id": "urn:storageos:StoragePort:d7e42",
                                      "link": {"rel": "self",
                                               "href": "/vdc/stor:"},
                                      "port": "50:00:09:73:00:18:95:19",
                                      'ip_address': "10.10.10.10",
                                      'tcp_port': '22'}},
                          {"hlu": 3,
                           "initiator": {"id": "urn:storageos:Initiator:13945",
                                         "link": {"rel": "self",
                                                  "href": "/comput"},
                                         "port": "iqn.1993-08.org.deb:01:222"},
                           "export": {"id": "urn:storageos:ExportGroup:2dbce2",
                                      "name": "ccgroup",
                                      "link": {"rel": "self",
                                               "href": "/block/expo"}},
                           "device": {"id": "urn:storageos:Volume:aa1fc84a-af",
                                      "link": {"rel": "self",
                                               "href": "/block/volumes/urn:s"},
                                      "wwn": "600009700001957015735330303535"},
                           "target": {"id": "urn:storageos:StoragePort:d7e42",
                                      "link": {"rel": "self",
                                               "href": "/vdc/stor:"},
                                      "port": "50:00:09:73:00:18:95:19",
                                      'ip_address': "10.10.10.10",
                                      'tcp_port': '22'}}]}

fcitl_itl_list = {"itl": [{"hlu": 3,
                           "initiator": {"id": "urn:storageos:Initiator:13945",
                                         "link": {"rel": "self",
                                                  "href": "/comput"},
                                         "port": "12:34:56:78:90:12:34:56"},
                           "export": {"id": "urn:storageos:ExportGroup:2dbce2",
                                      "name": "ccgroup",
                                      "link": {"rel": "self",
                                               "href": "/block/expo"}},
                           "device": {"id": "urn:storageos:Volume:aa1fc84a-af",
                                      "link": {"rel": "self",
                                               "href": "/block/volumes/urn:s"},
                                      "wwn": "600009700001957015735330303535"},
                           "target": {"id": "urn:storageos:StoragePort:d7e42",
                                      "link": {"rel": "self",
                                               "href": "/vdc/stor:"},
                                      "port": "12:34:56:78:90:12:34:56",
                                      'ip_address': "10.10.10.10",
                                      'tcp_port': '22'}},
                          {"hlu": 3,
                           "initiator": {"id": "urn:storageos:Initiator:13945",
                                         "link": {"rel": "self",
                                                  "href": "/comput"},
                                         "port": "12:34:56:78:90:12:34:56"},
                           "export": {"id": "urn:storageos:ExportGroup:2dbce2",
                                      "name": "ccgroup",
                                      "link": {"rel": "self",
                                               "href": "/block/expo"}},
                           "device": {"id": "urn:storageos:Volume:aa1fc84a-af",
                                      "link": {"rel": "self",
                                               "href": "/block/volumes/urn:s"},
                                      "wwn": "600009700001957015735330303535"},
                           "target": {"id": "urn:storageos:StoragePort:d7e42",
                                      "link": {"rel": "self",
                                               "href": "/vdc/stor:"},
                                      "port": "12:34:56:78:90:12:34:56",
                                      'ip_address': "10.10.10.10",
                                      'tcp_port': '22'}}]}


class EMCCoprHDISCSIDriverTest(test.TestCase):
    def setUp(self):
        super(EMCCoprHDISCSIDriverTest, self).setUp()
        self.create_vipr_setup()

    def create_vipr_setup(self):

        self.configuration = Mock()
        self.configuration.coprhd_hostname = "10.10.10.10"
        self.configuration.coprhd_port = "4443"
        self.configuration.volume_backend_name = "EMCCoprHDISCSIDriver"
        self.configuration.coprhd_username = "user-name"
        self.configuration.coprhd_password = "password"
        self.configuration.coprhd_tenant = "tenant"
        self.configuration.coprhd_project = "project"
        self.configuration.coprhd_varray = "varray"

        self.volume_type_id = self.create_coprhd_volume_type()
        #self.mock_vipr_cli_imports()

        from cinder.volume.drivers.coprhd import iscsi as coprhd_iscsi

        self.stubs.Set(coprhd_iscsi.EMCCoprHDISCSIDriver,
                       '_get_common_driver',
                       self._get_mocked_common_driver)
        self.driver = coprhd_iscsi.EMCCoprHDISCSIDriver(
            configuration=self.configuration)

    def mock_vipr_cli_imports(self):

        self.viprcli_mock = MagicMock()
        modules_to_be_mocked = {
            'viprcli': self.viprcli_mock,
            'viprcli.common': self.viprcli_mock.common,
            'viprcli.exportgroup': self.viprcli_mock.exportgroup,
            'viprcli.host': self.viprcli_mock.host,
            'viprcli.hostinitiators': self.viprcli_mock.hostinitiators,
            'viprcli.snapshot': self.viprcli_mock.snapshot,
            'viprcli.virtualarray': self.viprcli_mock.virtualarray,
            'viprcli.volume': self.viprcli_mock.volume,
            'viprcli.authentication': self.viprcli_mock.authentication}

        '''Fooling python interpreter for imports to go through,
        even if actual modules are not present in the system.
        '''
        self.module_patcher = patch.dict('sys.modules', modules_to_be_mocked)
        self.module_patcher.start()

    def tearDown(self):
        self._cleanUp()
        #self.module_patcher.stop()
        super(EMCCoprHDISCSIDriverTest, self).tearDown()

    def _cleanUp(self):
        self.delete_vipr_volume_type()

    def create_coprhd_volume_type(self):
        ctx = context.get_admin_context()
        vipr_volume_type = volume_types.create(ctx,
                                               "coprhd-volume-type",
                                               {'CoprHD:VPOOL': 'vpool_coprhd'})
        volume_id = vipr_volume_type['id']
        return volume_id

    def _get_mocked_common_driver(self):
        from cinder.volume.drivers.coprhd import common as coprhd_common

        class MockedEMCCoprHDDriverCommon(coprhd_common.
                                        EMCCoprHDDriverCommon):

            def __init__(self, protocol, default_backend_name,
                         configuration=None):

                super(MockedEMCCoprHDDriverCommon, self).__init__(
                    protocol, default_backend_name, configuration)

            def authenticate_user(self):
                pass

            def get_exports_count_by_initiators(self, initiator_ports):
                return 0
            
            def _get_coprhd_volume_name(self, vol, verbose=False):
                return "coprhd_vol_name"

            def init_volume_api(self):
                self.volume_api = Mock()
                self.volume_api.get.return_value = {
                    'name': 'source_test-vol1',
                    'size': 1,
                    'volume_name': 'source_test-vol1',
                    'id': '1234',
					'consistencygroup_id': '12345',
                    'provider_auth': None,
                    'project_id': 'project',
                    'display_name': 'source_test-vol1',
                    'display_description': 'test volume',
                    'volume_type_id': "vol_type_id-for-snap"}

            '''
            Mocking all CLI components methods is done here.
            Mock is a powerful python library that helps to mock the test
            data.
            Refer -
            http://www.voidspace.org.uk/python/mock/index.html#user-guide
            '''
            def init_coprhd_api_components(self):
                self.volume_obj = Mock()
                self.volume_obj.create.return_value = "volume_created"
                self.volume_obj.volume_query.return_value = "volume_uri"
                self.volume_obj.get_storageAttributes.return_value = ('block', 'volume_name') 
                self.volume_obj.storage_resource_query.return_value = "volume_uri"
                self.volume_obj.is_volume_detachable.return_value = False
                self.volume_obj.volume_clone_detach.return_value = 'detached'
                self.volume_obj.getTags.return_value \
                    = ["Openstack-vol", "Openstack-vol1"]
                self.volume_obj.tag.return_value = "tagged"
                self.volume_obj.clone.return_value = "volume-cloned"
                if(self.protocol == "iSCSI"):
                    self.volume_obj.get_exports_by_uri.return_value \
                        = iscsi_itl_list
                else:
                    self.volume_obj.get_exports_by_uri.return_value \
                        = fcitl_itl_list

                self.volume_obj.list_volumes.return_value = []
                self.volume_obj.show.return_value = {"id": "vol_id"}
                
                self.tag_obj = Mock()
                self.tag_obj.list_tags.return_value = ["Openstack-vol", "Openstack-vol1"]
                self.tag_obj.tag_resource.return_value = "Tagged"

                self.exportgroup_obj = Mock()
                self.exportgroup_obj.exportgroup_list.return_value \
                    = export_group_list
                self.exportgroup_obj.exportgroup_show.return_value \
                    = export_group_details_data

                self.host_obj = Mock()
                self.host_obj.list_by_tenant.return_value = []
                self.host_obj.search_by_name.return_value = []

                self.hostinitiator_obj = Mock()
                self.varray_obj = Mock()
                self.varray_obj.varray_show.return_value = varray_detail_data

                self.snapshot_obj = Mock()
                mocked_snap_obj = self.snapshot_obj.return_value
                mocked_snap_obj.storageResource_query.return_value \
                    = "resourceUri"
                mocked_snap_obj.snapshot_create.return_value \
                    = "snapshot_created"

        return MockedEMCCoprHDDriverCommon(
            protocol="iSCSI",
            default_backend_name="EMCViPRISCSIDriver",
            configuration=self.configuration)

    def delete_vipr_volume_type(self):
        ctx = context.get_admin_context()
        volume_types.destroy(ctx, self.volume_type_id)

    def get_test_volume_data(self):
        test_volume = {'name': 'test-vol1',
                       'size': 1,
                       'volume_name': 'test-vol1',
                       'id': '1',
					   'consistencygroup_id': None,
                       'provider_auth': None,
                       'project_id': 'project',
                       'display_name': 'test-vol1',
                       'display_description': 'test volume',
                       'volume_type_id': self.volume_type_id}
        return test_volume

    def get_source_test_volume_data(self):
        test_volume = {'name': 'source_test-vol1',
                       'size': 1,
                       'volume_name': 'source_test-vol1',
                       'id': '1234',
                       'provider_auth': None,
                       'project_id': 'project',
                       'display_name': 'source_test-vol1',
                       'display_description': 'test volume',
                       'volume_type_id': self.volume_type_id}
        return test_volume

    def get_clone_volume_data(self):
        clone_test_volume = {'name': 'clone-test-vol1',
                             'size': 1,
                             'volume_name': 'clone-test-vol1',
                             'id': '2',
                             'provider_auth': None,
                             'project_id': 'project',
                             'display_name': 'clone-test-vol1',
                             'display_description': 'clone test volume',
                             'volume_type_id': self.volume_type_id}
        return clone_test_volume

    def get_test_snapshot_data(self):
        test_snapshot = {'name': 'snapshot1',
                         'display_name': 'snapshot1',
                         'size': 1,
                         'id': '1111',
                         'volume_name': 'test-vol1',
                         'volume_id': '1234',
                         'volume': self.get_source_test_volume_data(),
                         'volume_size': 1,
                         'project_id': 'project'}
        return test_snapshot

    def get_connector_data(self):
        connector = {'ip': '10.0.0.2',
                     'initiator': 'iqn.1993-08.org.deb:01:222',
                     'wwpns': ["1234567890123456", "1234567890543211"],
                     'wwnns': ["223456789012345", "223456789054321"],
                     'host': 'fakehost'}
        return connector

    def test_create_destroy(self):
        volume = self.get_test_volume_data()

        self.driver.create_volume(volume)
        self.driver.delete_volume(volume)

    def test_get_volume_stats(self):
        vol_stats = self.driver.get_volume_stats(True)
        self.assertTrue(vol_stats['free_capacity_gb'], 'unknown')

    def test_create_volume_clone(self):
        src_volume_data = self.get_test_volume_data()
        clone_volume_data = self.get_clone_volume_data()
        self.driver.create_volume(src_volume_data)
        self.driver.create_cloned_volume(clone_volume_data, src_volume_data)
        self.driver.delete_volume(src_volume_data)
        self.driver.delete_volume(clone_volume_data)

    def test_create_destroy_snapshot(self):
        volume_data = self.get_test_volume_data()
        snapshot_data = self.get_test_snapshot_data()

        self.driver.create_volume(volume_data)
        self.driver.create_snapshot(snapshot_data)
        self.driver.delete_snapshot(snapshot_data)
        self.driver.delete_volume(volume_data)

    def test_create_volume_from_snapshot(self):

        src_vol_data = self.get_source_test_volume_data()
        self.driver.create_volume(src_vol_data)

        volume_data = self.get_test_volume_data()
        snapshot_data = self.get_test_snapshot_data()

        self.driver.create_snapshot(snapshot_data)
        self.driver.create_volume_from_snapshot(volume_data, snapshot_data)

        self.driver.delete_snapshot(snapshot_data)
        self.driver.delete_volume(src_vol_data)
        self.driver.delete_volume(volume_data)

    def test_extend_volume(self):
        volume_data = self.get_test_volume_data()
        self.driver.create_volume(volume_data)
        self.driver.extend_volume(volume_data, 2)
        self.driver.delete_volume(volume_data)

    def test_initialize_and_terminate_connection(self):
        connector_data = self.get_connector_data()
        volume_data = self.get_test_volume_data()

        self.driver.create_volume(volume_data)
        self.driver.initialize_connection(volume_data, connector_data)
        self.driver.terminate_connection(volume_data, connector_data)
        self.driver.delete_volume(volume_data)


class EMCViPRFCDriverTest(test.TestCase):

    def setUp(self):
        super(EMCViPRFCDriverTest, self).setUp()
        self.create_vipr_setup()

    def create_vipr_setup(self):

        self.configuration = Mock()
        self.configuration.vipr_hostname = "10.10.10.10"
        self.configuration.vipr_port = "4443"
        self.configuration.volume_backend_name = "EMCViPRFCDriver"
        self.configuration.vipr_cookiedir = "/tmp"
        self.configuration.vipr_username = "user-name"
        self.configuration.vipr_password = "password"
        self.configuration.vipr_tenant = "tenant"
        self.configuration.vipr_project = "project"
        self.configuration.vipr_varray = "varray"
        self.configuration.vipr_cli_path = "/opt/storageos/cli/bin"

        self.volume_type_id = self.create_vipr_volume_type()
        self.mock_vipr_cli_imports()

        from cinder.volume.drivers.emc.vipr import fc as vipr_fc

        self.stubs.Set(vipr_fc.EMCViPRFCDriver,
                       '_get_common_driver',
                       self._get_mocked_common_driver)
        self.driver = vipr_fc.EMCViPRFCDriver(
            configuration=self.configuration)

    def mock_vipr_cli_imports(self):

        self.viprcli_mock = MagicMock()
        modules_to_be_mocked = {
            'viprcli': self.viprcli_mock,
            'viprcli.common': self.viprcli_mock.common,
            'viprcli.exportgroup': self.viprcli_mock.exportgroup,
            'viprcli.host': self.viprcli_mock.host,
            'viprcli.hostinitiators': self.viprcli_mock.hostinitiators,
            'viprcli.snapshot': self.viprcli_mock.snapshot,
            'viprcli.virtualarray': self.viprcli_mock.virtualarray,
            'viprcli.volume': self.viprcli_mock.volume,
            'viprcli.authentication': self.viprcli_mock.authentication}

        self.module_patcher = patch.dict('sys.modules', modules_to_be_mocked)
        self.module_patcher.start()

    def tearDown(self):
        self._cleanUp()
        self.module_patcher.stop()
        super(EMCViPRFCDriverTest, self).tearDown()

    def _cleanUp(self):
        self.delete_vipr_volume_type()

    def create_vipr_volume_type(self):
        ctx = context.get_admin_context()
        vipr_volume_type = volume_types.create(ctx,
                                               "vipr-volume-type",
                                               {'ViPR:VPOOL': 'vpool_vipr'})
        volume_id = vipr_volume_type['id']
        return volume_id

    def _get_mocked_common_driver(self):
        from cinder.volume.drivers.emc.vipr import common as vipr_common

        class MockedEMCViPRDriverCommon(vipr_common.
                                        EMCViPRDriverCommon):

            def __init__(self, protocol, default_backend_name,
                         configuration=None):

                super(MockedEMCViPRDriverCommon, self).__init__(
                    protocol, default_backend_name, configuration)

            def check_for_vipr_cli_path(self):
                pass

            def get_exports_count_by_initiators(self, initiator_ports):
                return 0
            
            def _get_coprhd_volume_name(self, vol, verbose=False):
                return "coprhd_vol_name"

            def init_volume_api(self):
                self.volume_api = Mock()
                self.volume_api.get.return_value = {
                    'name': 'source_test-vol1',
                    'size': 1,
                    'volume_name': 'source_test-vol1',
                    'id': '1234',
                    'provider_auth': None,
                    'project_id': 'project',
                    'display_name': 'source_test-vol1',
                    'display_description': 'test volume',
                    'volume_type_id': "vol_type_id-for-snap"}

            '''
            Mocking all CLI components methods is done here.
            Mock is a powerful python library that helps to mock the test
            data.
            Refer -
            http://www.voidspace.org.uk/python/mock/index.html#user-guide
            '''
            def init_vipr_cli_components(self):
                self.volume_obj = Mock()
                self.volume_obj.create.return_value = "volume_created"
                self.volume_obj.delete.return_value = "volume_deleted"
                self.volume_obj.getTags.return_value \
                    = ["Openstack-vol", "Openstack-vol1"]
                self.volume_obj.tag.return_value = "tagged"
                self.volume_obj.clone.return_value = "volume-cloned"
                if(self.protocol == "iSCSI"):
                    self.volume_obj.get_exports_by_uri.return_value \
                        = iscsi_itl_list
                else:
                    self.volume_obj.get_exports_by_uri.return_value \
                        = fcitl_itl_list

                self.volume_obj.list_volumes.return_value = []
                self.volume_obj.show.return_value = {"id": "vol_id"}

                self.exportgroup_obj = Mock()
                self.exportgroup_obj.exportgroup_list.return_value \
                    = export_group_list
                self.exportgroup_obj.exportgroup_show.return_value \
                    = export_group_details_data
                self.host_obj = Mock()
                self.host_obj.list_by_tenant.return_value = []
                self.host_obj.search_by_name.return_value = []

                self.hostinitiator_obj = Mock()
                self.varray_obj = Mock()
                self.varray_obj.varray_show.return_value = varray_detail_data

                self.snapshot_obj = Mock()
                mocked_snap_obj = self.snapshot_obj.return_value
                mocked_snap_obj.storageResource_query.return_value \
                    = "resourceUri"
                mocked_snap_obj.snapshot_create.return_value \
                    = "snapshot_created"

        return MockedEMCViPRDriverCommon(
            protocol="FC",
            default_backend_name="EMCViPRFCDriver",
            configuration=self.configuration)

    def delete_vipr_volume_type(self):
        ctx = context.get_admin_context()
        volume_types.destroy(ctx, self.volume_type_id)

    def get_test_volume_data(self):
        test_volume = {'name': 'test-vol1',
                       'size': 1,
                       'volume_name': 'test-vol1',
                       'id': '1',
					   'consistencygroup_id': None,
                       'provider_auth': None,
                       'project_id': 'project',
                       'display_name': 'test-vol1',
                       'display_description': 'test volume',
                       'volume_type_id': self.volume_type_id}
        return test_volume

    def get_clone_volume_data(self):
        clone_test_volume = {'name': 'clone-test-vol1',
                             'size': 1,
                             'volume_name': 'clone-test-vol1',
                             'id': '2',
                             'provider_auth': None,
                             'project_id': 'project',
                             'display_name': 'clone-test-vol1',
                             'display_description': 'clone test volume',
                             'volume_type_id': self.volume_type_id}
        return clone_test_volume

    def get_test_snapshot_data(self):
        test_snapshot = {'name': 'snapshot1',
                         'display_name': 'snapshot1',
                         'size': 1,
                         'id': '1111',
                         'volume_name': 'test-vol1',
                         'volume_id': '1234',
                         'volume': self.get_source_test_volume_data(),
                         'volume_size': 1,
                         'project_id': 'project'}
        return test_snapshot

    def get_source_test_volume_data(self):
        test_volume = {'name': 'source_test-vol1',
                       'size': 1,
                       'volume_name': 'source_test-vol1',
                       'id': '1234',
                       'provider_auth': None,
                       'project_id': 'project',
                       'display_name': 'source_test-vol1',
                       'display_description': 'test volume',
                       'volume_type_id': self.volume_type_id}
        return test_volume

    def get_connector_data(self):
        connector = {'ip': '10.0.0.2',
                     'initiator': 'iqn.1993-08.org.deb:01:222',
                     'wwpns': ["1234567890123456", "1234567890543211"],
                     'wwnns': ["223456789012345", "223456789054321"],
                     'host': 'fakehost'}
        return connector

    def test_create_destroy(self):
        volume = self.get_test_volume_data()

        self.driver.create_volume(volume)
        self.driver.delete_volume(volume)

    def test_get_volume_stats(self):
        vol_stats = self.driver.get_volume_stats(True)
        self.assertTrue(vol_stats['free_capacity_gb'], 'unknown')

    def test_create_volume_clone(self):

        src_volume_data = self.get_test_volume_data()
        clone_volume_data = self.get_clone_volume_data()
        self.driver.create_volume(src_volume_data)
        self.driver.create_cloned_volume(clone_volume_data, src_volume_data)
        self.driver.delete_volume(src_volume_data)
        self.driver.delete_volume(clone_volume_data)

    def test_create_destroy_snapshot(self):

        volume_data = self.get_test_volume_data()
        snapshot_data = self.get_test_snapshot_data()

        self.driver.create_volume(volume_data)
        self.driver.create_snapshot(snapshot_data)
        self.driver.delete_snapshot(snapshot_data)
        self.driver.delete_volume(volume_data)

    def test_create_volume_from_snapshot(self):
        src_vol_data = self.get_source_test_volume_data()
        self.driver.create_volume(src_vol_data)

        volume_data = self.get_test_volume_data()
        snapshot_data = self.get_test_snapshot_data()

        self.driver.create_snapshot(snapshot_data)
        self.driver.create_volume_from_snapshot(volume_data, snapshot_data)

        self.driver.delete_snapshot(snapshot_data)
        self.driver.delete_volume(src_vol_data)
        self.driver.delete_volume(volume_data)

    def test_extend_volume(self):
        volume_data = self.get_test_volume_data()
        self.driver.create_volume(volume_data)
        self.driver.extend_volume(volume_data, 2)
        self.driver.delete_volume(volume_data)

    def test_initialize_and_terminate_connection(self):

        connector_data = self.get_connector_data()
        volume_data = self.get_test_volume_data()

        self.driver.create_volume(volume_data)
        self.driver.initialize_connection(volume_data, connector_data)
        self.driver.terminate_connection(volume_data, connector_data)
        self.driver.delete_volume(volume_data)
