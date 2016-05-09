#!/usr/bin/python

'''
 * Copyright 2016 EMC Corporation
 * Copyright 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
'''

import os
import sys
import requests
import cookielib
from cinder.volume.drivers.emc.coprhd import commoncoprhdapi as common
import getpass
from cinder.volume.drivers.emc.coprhd.commoncoprhdapi import SOSError
from requests.exceptions import SSLError
from requests.exceptions import ConnectionError
from requests.exceptions import TooManyRedirects
from requests.exceptions import Timeout
import socket
import json
import ConfigParser


class Authentication(object):

    '''
    The class definition for authenticating the specified user
    '''

    # Commonly used URIs for the 'Authentication' module
    URI_SERVICES_BASE = ''
    URI_AUTHENTICATION = '/login'
    URI_VDC_AUTHN_PROFILE = URI_SERVICES_BASE + '/vdc/admin/authnproviders'
    URI_VDC_AUTHN_PROFILES = (URI_SERVICES_BASE +
                              '/vdc/admin/authnproviders/{0}')
    URI_VDC_AUTHN_PROFILES_FORCE_UPDATE = (URI_SERVICES_BASE +
                                           '/vdc/admin/authnproviders/{0}{1}')
    URI_VDC_ROLES = URI_SERVICES_BASE + '/vdc/role-assignments'

    URI_LOGOUT = URI_SERVICES_BASE + '/logout'

    URI_USER_GROUP = URI_SERVICES_BASE + '/vdc/admin/user-groups'
    URI_USER_GROUP_ID = URI_USER_GROUP + '/{0}'

    HEADERS = {'Content-Type': 'application/json',
               'ACCEPT': 'application/json', 'X-EMC-REST-CLIENT': 'TRUE'}
    SEARCH_SCOPE = ['ONELEVEL', 'SUBTREE']
    BOOL_VALS = ['true', 'false']
    ZONE_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN', 'SYSTEM_MONITOR',
                  'SYSTEM_AUDITOR']
    MODES = ['ad', 'ldap', 'keystone']

    def __init__(self, ipAddr, port):
        '''
        Constructor: takes IP address and port of the ViPR instance.
        These are needed to make http requests for REST API
        '''
        self.__ipAddr = ipAddr
        self.__port = port

    def authenticate_user(self, username, password, cookiedir, cookiefile):
        '''
        Makes REST API call to generate the cookiefile for the
        specified user after validation.
        Returns:
            SUCCESS OR FAILURE
        '''
        SEC_REDIRECT = 302
        SEC_AUTHTOKEN_HEADER = 'X-SDS-AUTH-TOKEN'
        LB_API_PORT = 4443
        # Port on which load-balancer/reverse-proxy listens to all incoming
        # requests for ViPR REST APIs
        APISVC_PORT = 8443  # Port on which apisvc listens to incoming requests

        cookiejar = cookielib.LWPCookieJar()

        url = ('https://' + str(self.__ipAddr) + ':' + str(self.__port) +
               self.URI_AUTHENTICATION)

        try:
            if(self.__port == APISVC_PORT):
                login_response = requests.get(
                    url, headers=self.HEADERS, verify=False,
                    auth=(username, password), cookies=cookiejar,
                    allow_redirects=False, timeout=common.TIMEOUT_SEC)
                if(login_response.status_code == SEC_REDIRECT):
                    location = login_response.headers['Location']
                    if(not location):
                        raise SOSError(
                            SOSError.HTTP_ERR, "The redirect location of " +
                            "the authentication service is not provided")
                    # Make the second request
                    login_response = requests.get(
                        location, headers=self.HEADERS, verify=False,
                        cookies=cookiejar, allow_redirects=False,
                        timeout=common.TIMEOUT_SEC)
                    if(not (login_response.status_code ==
                            requests.codes['unauthorized'])):
                        raise SOSError(
                            SOSError.HTTP_ERR, "The authentication service" +
                            " failed to reply with 401")

                    # Now provide the credentials
                    login_response = requests.get(
                        location, headers=self.HEADERS,
                        auth=(username, password), verify=False,
                        cookies=cookiejar, allow_redirects=False,
                        timeout=common.TIMEOUT_SEC)
                    if(not login_response.status_code == SEC_REDIRECT):
                        raise SOSError(
                            SOSError.HTTP_ERR,
                            "Access forbidden: Authentication required")
                    location = login_response.headers['Location']
                    if(not location):
                        raise SOSError(
                            SOSError.HTTP_ERR, "The authentication service" +
                            " failed to provide the location of the service" +
                            " URI when redirecting back")
                    authToken = login_response.headers[SEC_AUTHTOKEN_HEADER]
                    if (not authToken):
                        details_str = self.extract_error_detail(login_response)
                        raise SOSError(SOSError.HTTP_ERR,
                                       "The token is not generated" +
                                       " by authentication service." + details_str)
                    # Make the final call to get the page with the token
                    newHeaders = self.HEADERS
                    newHeaders[SEC_AUTHTOKEN_HEADER] = authToken
                    login_response = requests.get(
                        location, headers=newHeaders, verify=False,
                        cookies=cookiejar, allow_redirects=False,
                        timeout=common.TIMEOUT_SEC)
                    if(login_response.status_code != requests.codes['ok']):
                        raise SOSError(
                            SOSError.HTTP_ERR, "Login failure code: " +
                            str(login_response.status_code) + " Error: " +
                            login_response.text)
            elif(self.__port == LB_API_PORT):
                login_response = requests.get(
                    url, headers=self.HEADERS, verify=False,
                    cookies=cookiejar, allow_redirects=False)

                if(login_response.status_code ==
                   requests.codes['unauthorized']):
                    # Now provide the credentials
                    login_response = requests.get(
                        url, headers=self.HEADERS, auth=(username, password),
                        verify=False, cookies=cookiejar, allow_redirects=False)
                authToken = None
                if(SEC_AUTHTOKEN_HEADER in login_response.headers):
                    authToken = login_response.headers[SEC_AUTHTOKEN_HEADER]
            else:
                raise SOSError(
                    SOSError.HTTP_ERR,
                    "Incorrect port number.  Load balanced port is: " +
                    str(LB_API_PORT) + ", api service port is: " +
                    str(APISVC_PORT) + ".")

            if (not authToken):
                details_str = self.extract_error_detail(login_response)
                raise SOSError(
                    SOSError.HTTP_ERR,
                    "The token is not generated by authentication service."
                    + details_str)

            if (login_response.status_code != requests.codes['ok']):
                error_msg = None
                if(login_response.status_code == 401):
                    error_msg = "Access forbidden: Authentication required"
                elif(login_response.status_code == 403):
                    error_msg = ("Access forbidden: You don't have" +
                                 " sufficient privileges to perform" +
                                 " this operation")
                elif(login_response.status_code == 500):
                    error_msg = "Bourne internal server error"
                elif(login_response.status_code == 404):
                    error_msg = "Requested resource is currently unavailable"
                elif(login_response.status_code == 405):
                    error_msg = ("GET method is not supported by resource: " +
                                 url)
                elif(login_response.status_code == 503):
                    error_msg = ("Service temporarily unavailable:" +
                                 " The server is temporarily unable" +
                                 " to service your request")
                else:
                    error_msg = login_response.text
                    if isinstance(error_msg, unicode):
                        error_msg = error_msg.encode('utf-8')
                raise SOSError(SOSError.HTTP_ERR, "HTTP code: " +
                               str(login_response.status_code) +
                               ", response: " + str(login_response.reason) +
                               " [" + str(error_msg) + "]")

        except (SSLError, socket.error, ConnectionError, Timeout) as e:
            raise SOSError(SOSError.HTTP_ERR, str(e))

        form_cookiefile = None
        parentshellpid = None
        installdir_cookie = None
        if sys.platform.startswith('linux'):
            parentshellpid = os.getppid()
            if(cookiefile is None):
                if (parentshellpid is not None):
                    cookiefile = str(username) + 'cookie' + str(parentshellpid)
                else:
                    cookiefile = str(username) + 'cookie'
            form_cookiefile = cookiedir + '/' + cookiefile
            if (parentshellpid is not None):
                installdir_cookie = '/cookie/' + str(parentshellpid)
            else:
                installdir_cookie = '/cookie/cookiefile'
        elif sys.platform.startswith('win'):
            if (cookiefile is None):
                cookiefile = str(username) + 'cookie'
            form_cookiefile = cookiedir + '\\' + cookiefile
            installdir_cookie = '\\cookie\\cookiefile'
        else:
            if (cookiefile is None):
                cookiefile = str(username) + 'cookie'
            form_cookiefile = cookiedir + '/' + cookiefile
            installdir_cookie = '/cookie/cookiefile'
        try:
            if(common.create_file(form_cookiefile)):
                tokenFile = open(form_cookiefile, "w")
                if(tokenFile):
                    tokenFile.write(authToken)
                    tokenFile.close()
                else:
                    raise SOSError(SOSError.NOT_FOUND_ERR,
                                   " Failed to save the cookie file path "
                                   + form_cookiefile)

        except (OSError) as e:
            raise SOSError(e.errno, cookiedir + " " + e.strerror)
        except IOError as e:
            raise SOSError(e.errno, e.strerror)

        if (common.create_file(form_cookiefile)):

            # cookiejar.save(form_cookiefile, ignore_discard=True,
            #               ignore_expires=True);
            #sos_cli_install_dir = common.getenv('VIPR_CLI_INSTALL_DIR')
            sos_cli_install_dir = "."

            if (sos_cli_install_dir):
                if (not os.path.isdir(sos_cli_install_dir)):
                    raise SOSError(SOSError.NOT_FOUND_ERR,
                                   sos_cli_install_dir + " : Not a directory")
                config_file = sos_cli_install_dir + installdir_cookie
                if (common.create_file(config_file)):
                    fd = open(config_file, 'w+')
                    if (fd):
                        fd_content = os.path.abspath(form_cookiefile) + '\n'
                        fd.write(fd_content)
                        fd.close()
                        ret_val = username +\
                            ' : Authenticated Successfully\n' +\
                            form_cookiefile + ' : Cookie saved successfully'
                    else:
                        raise SOSError(
                            SOSError.NOT_FOUND_ERR, config_file +
                            " : Failed to save the cookie file path " +
                            form_cookiefile)
                else:
                    raise SOSError(SOSError.NOT_FOUND_ERR,
                                   config_file + " : Failed to create file")

            else:
                raise SOSError(
                    SOSError.NOT_FOUND_ERR,
                    "VIPR_CLI_INSTALL_DIR is not set.")
        return ret_val

    def extract_error_detail(self, login_response):
        details_str = ""
        try:
            if(login_response.content):
                json_object = common.json_decode(login_response.content)
                if(json_object.has_key('details')):
                    details_str = json_object['details']

            return details_str
        except SOSError as e:
            return details_str
