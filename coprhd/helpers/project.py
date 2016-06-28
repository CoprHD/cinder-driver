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


from cinder.i18n import _
from cinder.volume.drivers.coprhd.helpers import commoncoprhdapi as common


class Project(common.CoprHDResource):

    # Commonly used URIs for the 'Project' module
    URI_PROJECT_LIST = '/tenants/{0}/projects'
    URI_PROJECT = '/projects/{0}'

    def project_query(self, name):
        """Retrieves UUID of project based on its name.

        Parameters:
            name: name of project
        Returns: UUID of project
        Throws:
            CoprHdError - when project name is not found
        """
        if common.is_uri(name):
            return name
        (tenant_name, project_name) = common.get_parent_child_from_xpath(name)

        from cinder.volume.drivers.coprhd.helpers.tenant import Tenant
        tenant_obj = Tenant(self.ipaddr, self.port)

        tenant_uri = tenant_obj.tenant_query(tenant_name)
        projects = self.project_list(tenant_uri)
        if projects and len(projects) > 0:
            for project in projects:
                if project:
                    project_detail = self.project_show_by_uri(
                        project['id'])
                    if(project_detail and
                       project_detail['name'] == project_name):
                        return project_detail['id']
        raise common.CoprHdError(common.CoprHdError.NOT_FOUND_ERR, (_(
                                 "Project: %s not found") % project_name))

    def project_list(self, tenant_name):
        """Makes REST API call and retrieves projects based on tenant UUID.

        Parameters: None
        Returns:
            List of project UUIDs in JSON response payload
        """
        from cinder.volume.drivers.coprhd.helpers.tenant import Tenant
        tenant_obj = Tenant(self.ipaddr, self.port)
        tenant_uri = tenant_obj.tenant_query(tenant_name)
        (s, h) = common.service_json_request(self.ipaddr, self.port, "GET",
                                             Project.URI_PROJECT_LIST.format(
                                                 tenant_uri),
                                             None)
        o = common.json_decode(s)

        if "project" in o:
            return common.get_list(o, 'project')
        return []

    def project_show_by_uri(self, uri):
        """Makes REST API call and retrieves project derails based on UUID.

        Parameters:
            uri: UUID of project
        Returns:
            Project details in JSON response payload
        """

        (s, h) = common.service_json_request(self.ipaddr, self.port,
                                             "GET",
                                             Project.URI_PROJECT.format(uri),
                                             None)
        o = common.json_decode(s)
        inactive = common.get_node_value(o, 'inactive')
        if inactive:
            return None

        return o
