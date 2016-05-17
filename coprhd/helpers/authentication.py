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


import cookielib
import six
import socket

import requests
from requests.exceptions import ConnectionError
from requests.exceptions import SSLError
from requests.exceptions import Timeout

from cinder.volume.drivers.emc.coprhd.helpers import commoncoprhdapi as common
from cinder.volume.drivers.emc.coprhd.helpers.commoncoprhdapi \
    import CoprHdError


class Authentication(object):

    # Commonly used URIs for the 'Authentication' module
    URI_SERVICES_BASE = ''
    URI_AUTHENTICATION = '/login'

    HEADERS = {'Content-Type': 'application/json',
               'ACCEPT': 'application/json', 'X-EMC-REST-CLIENT': 'TRUE'}

    def __init__(self, ipaddr, port):
        '''Constructor: takes IP address and port of the CoprHD instance

        These are needed to make http requests for REST API
        '''
        self.__ipaddr = ipaddr
        self.__port = port

    def authenticate_user(self, username, password):
        '''Makes REST API call to generate the authentication token

        Authentication token is generated for the specified user after
        validation

        Returns:
            SUCCESS OR FAILURE
        '''
        SEC_REDIRECT = 302
        SEC_AUTHTOKEN_HEADER = 'X-SDS-AUTH-TOKEN'
        LB_API_PORT = 4443
        # Port on which load-balancer/reverse-proxy listens to all incoming
        # requests for CoprHD REST APIs
        APISVC_PORT = 8443  # Port on which apisvc listens to incoming requests

        cookiejar = cookielib.LWPCookieJar()

        url = ('https://' + str(self.__ipaddr) + ':' + str(self.__port) +
               self.URI_AUTHENTICATION)

        try:
            if self.__port == APISVC_PORT:
                login_response = requests.get(
                    url, headers=self.HEADERS, verify=False,
                    auth=(username, password), cookies=cookiejar,
                    allow_redirects=False, timeout=common.TIMEOUT_SEC)
                if login_response.status_code == SEC_REDIRECT:
                    location = login_response.headers['Location']
                    if not location:
                        raise CoprHdError(
                            CoprHdError.HTTP_ERR, "The redirect location of " +
                            "the authentication service is not provided")
                    # Make the second request
                    login_response = requests.get(
                        location, headers=self.HEADERS, verify=False,
                        cookies=cookiejar, allow_redirects=False,
                        timeout=common.TIMEOUT_SEC)
                    if(not (login_response.status_code ==
                            requests.codes['unauthorized'])):
                        raise CoprHdError(
                            CoprHdError.HTTP_ERR, "The authentication " +
                            " service failed to reply with 401")

                    # Now provide the credentials
                    login_response = requests.get(
                        location, headers=self.HEADERS,
                        auth=(username, password), verify=False,
                        cookies=cookiejar, allow_redirects=False,
                        timeout=common.TIMEOUT_SEC)
                    if not login_response.status_code == SEC_REDIRECT:
                        raise CoprHdError(
                            CoprHdError.HTTP_ERR,
                            "Access forbidden: Authentication required")
                    location = login_response.headers['Location']
                    if not location:
                        raise CoprHdError(
                            CoprHdError.HTTP_ERR, "The authentication" +
                            " service failed to provide the location of" +
                            " the service URI when redirecting back")
                    authtoken = login_response.headers[SEC_AUTHTOKEN_HEADER]
                    if not authtoken:
                        details_str = self.extract_error_detail(login_response)
                        raise CoprHdError(CoprHdError.HTTP_ERR,
                                          "The token is not generated" +
                                          " by authentication service." +
                                          details_str)
                    # Make the final call to get the page with the token
                    new_headers = self.HEADERS
                    new_headers[SEC_AUTHTOKEN_HEADER] = authtoken
                    login_response = requests.get(
                        location, headers=new_headers, verify=False,
                        cookies=cookiejar, allow_redirects=False,
                        timeout=common.TIMEOUT_SEC)
                    if login_response.status_code != requests.codes['ok']:
                        raise CoprHdError(
                            CoprHdError.HTTP_ERR, "Login failure code: " +
                            str(login_response.status_code) + " Error: " +
                            login_response.text)
            elif self.__port == LB_API_PORT:
                login_response = requests.get(
                    url, headers=self.HEADERS, verify=False,
                    cookies=cookiejar, allow_redirects=False)

                if(login_response.status_code ==
                   requests.codes['unauthorized']):
                    # Now provide the credentials
                    login_response = requests.get(
                        url, headers=self.HEADERS, auth=(username, password),
                        verify=False, cookies=cookiejar, allow_redirects=False)
                authtoken = None
                if SEC_AUTHTOKEN_HEADER in login_response.headers:
                    authtoken = login_response.headers[SEC_AUTHTOKEN_HEADER]
            else:
                raise CoprHdError(
                    CoprHdError.HTTP_ERR,
                    "Incorrect port number.  Load balanced port is: " +
                    str(LB_API_PORT) + ", api service port is: " +
                    str(APISVC_PORT) + ".")

            if not authtoken:
                details_str = self.extract_error_detail(login_response)
                raise CoprHdError(
                    CoprHdError.HTTP_ERR,
                    "The token is not generated by authentication service." +
                    details_str)

            if login_response.status_code != requests.codes['ok']:
                error_msg = None
                if login_response.status_code == 401:
                    error_msg = "Access forbidden: Authentication required"
                elif login_response.status_code == 403:
                    error_msg = ("Access forbidden: You don't have" +
                                 " sufficient privileges to perform" +
                                 " this operation")
                elif login_response.status_code == 500:
                    error_msg = "Bourne internal server error"
                elif login_response.status_code == 404:
                    error_msg = "Requested resource is currently unavailable"
                elif login_response.status_code == 405:
                    error_msg = ("GET method is not supported by resource: " +
                                 url)
                elif login_response.status_code == 503:
                    error_msg = ("Service temporarily unavailable:" +
                                 " The server is temporarily unable" +
                                 " to service your request")
                else:
                    error_msg = login_response.text
                    if isinstance(error_msg, unicode):
                        error_msg = error_msg.encode('utf-8')
                raise CoprHdError(CoprHdError.HTTP_ERR, "HTTP code: " +
                                  str(login_response.status_code) +
                                  ", response: " + str(login_response.reason) +
                                  " [" + str(error_msg) + "]")

        except (SSLError, socket.error, ConnectionError, Timeout) as e:
            raise CoprHdError(CoprHdError.HTTP_ERR, six.text_type(e))

        return authtoken

    def extract_error_detail(self, login_response):
        details_str = ""
        try:
            if login_response.content:
                json_object = common.json_decode(login_response.content)
                if 'details' in json_object:
                    details_str = json_object['details']

            return details_str
        except CoprHdError:
            return details_str
