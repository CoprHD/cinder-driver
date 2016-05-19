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
Contains some commonly used utility methods
'''
import cookielib
import json
import re
import six
import socket
import sys
from threading import Timer

import oslo_serialization
import requests
from requests.exceptions import ConnectionError
from requests.exceptions import SSLError
from requests.exceptions import Timeout
from requests.exceptions import TooManyRedirects
from urihelper import singletonURIHelperInstance


PROD_NAME = 'storageos'

TIMEOUT_SEC = 20  # 20 SECONDS
IS_TASK_TIMEOUT = False

global AUTH_TOKEN


def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


def json_decode(rsp):
    '''Used to decode the JSON encoded response

    '''

    o = ""
    try:
        o = json.loads(rsp, object_hook=_decode_dict)
    except ValueError:
        raise CoprHdError(CoprHdError.VALUE_ERR,
                          "Failed to recognize JSON payload:\n[" + rsp + "]")
    return o


def service_json_request(ip_addr, port, http_method, uri, body,
                         contenttype='application/json', customheaders=None):
    '''Used to make an HTTP request and get the response

    The message body is encoded in JSON format
    Parameters:
        ip_addr: IP address or host name of the server
        port: port number of the server on which it
            is listening to HTTP requests
        http_method: one of GET, POST, PUT, DELETE
        uri: the request URI
        body: the request payload
    Returns:
        a tuple of two elements: (response body, response headers)
    Throws: CoprHdError in case of HTTP errors with err_code 3
    '''

    SEC_AUTHTOKEN_HEADER = 'X-SDS-AUTH-TOKEN'

    headers = {'Content-Type': contenttype,
               'ACCEPT': 'application/json, application/octet-stream',
               'X-EMC-REST-CLIENT': 'TRUE'}

    if customheaders:
        headers.update(customheaders)

    try:
        protocol = "https://"
        if str(port) == '8080':
            protocol = "http://"
        url = protocol + ip_addr + ":" + str(port) + uri

        cookiejar = cookielib.LWPCookieJar()
        headers[SEC_AUTHTOKEN_HEADER] = AUTH_TOKEN

        if http_method == 'GET':
            response = requests.get(url, headers=headers, verify=False,
                                    cookies=cookiejar)
        elif http_method == 'POST':
            response = requests.post(url, data=body, headers=headers,
                                     verify=False, cookies=cookiejar)
        elif http_method == 'PUT':
            response = requests.put(url, data=body, headers=headers,
                                    verify=False, cookies=cookiejar)
        elif http_method == 'DELETE':

            response = requests.delete(url, headers=headers, verify=False,
                                       cookies=cookiejar)
        else:
            raise CoprHdError(CoprHdError.HTTP_ERR,
                              "Unknown/Unsupported HTTP method: " +
                              http_method)

        if response.status_code == requests.codes['ok'] or \
                response.status_code == 202:
            return (response.text, response.headers)

        error_msg = None
        if response.status_code == 500:
            responseText = json_decode(response.text)
            errorDetails = ""
            if 'details' in responseText:
                errorDetails = responseText['details']
            error_msg = "CoprHD internal server error. Error details: " + \
                errorDetails
        elif response.status_code == 401:
            error_msg = "Access forbidden: Authentication required"
        elif response.status_code == 403:
            error_msg = ""
            errorDetails = ""
            errorDescription = ""

            responseText = json_decode(response.text)

            if 'details' in responseText:
                errorDetails = responseText['details']
                error_msg = error_msg + "Error details: " + errorDetails
            elif 'description' in responseText:
                errorDescription = responseText['description']
                error_msg = error_msg + "Error description: " + \
                    errorDescription
            else:
                error_msg = "Access forbidden: You don't have" + \
                    " sufficient privileges to perform this operation"

        elif response.status_code == 404:
            error_msg = "Requested resource not found"
        elif response.status_code == 405:
            error_msg = str(response.text)
        elif response.status_code == 503:
            error_msg = ""
            errorDetails = ""
            errorDescription = ""

            responseText = json_decode(response.text)

            if 'code' in responseText:
                errorCode = responseText['code']
                error_msg = error_msg + "Error " + str(errorCode)

            if 'details' in responseText:
                errorDetails = responseText['details']
                error_msg = error_msg + ": " + errorDetails
            elif 'description' in responseText:
                errorDescription = responseText['description']
                error_msg = error_msg + ": " + errorDescription
            else:
                error_msg = "Service temporarily unavailable:" + \
                            " The server is temporarily unable to " + \
                            " service your request"
        else:
            error_msg = response.text
            if isinstance(error_msg, unicode):
                error_msg = error_msg.encode('utf-8')
        raise CoprHdError(CoprHdError.HTTP_ERR, "HTTP code: " +
                          str(response.status_code) +
                          ", " + response.reason + " [" + error_msg + "]")

    except (CoprHdError, socket.error, SSLError,
            ConnectionError, TooManyRedirects, Timeout) as e:
        raise CoprHdError(CoprHdError.HTTP_ERR, six.text_type(e))
    # TODO(Ravi) : Either following exception should have proper message or
    # IOError should just be combined with the above statement
    except IOError as e:
        raise CoprHdError(CoprHdError.HTTP_ERR, six.text_type(e))


def is_uri(name):
    '''Checks whether the name is a UUID or not

    Returns:
        True if name is UUID, False otherwise
    '''
    try:
        (urn, prod, trailer) = name.split(':', 2)
        return (urn == 'urn' and prod == PROD_NAME)
    except Exception:
        return False


def format_json_object(obj):
    '''Formats JSON object to make it readable by proper indentation

    Parameters:
        obj - JSON object
    Returns:
        a string of  formatted JSON object
    '''
    return oslo_serialization.jsonutils.dumps(obj, sort_keys=True, indent=3)


def get_parent_child_from_xpath(name):
    '''Returns the parent and child elements from XPath

    '''
    if '/' in name:
        (pname, label) = name.rsplit('/', 1)
    else:
        pname = None
        label = name
    return (pname, label)


def to_bytes(in_str):
    """Converts a size to bytes

    Parameters:
        in_str - a number suffixed with a unit: {number}{unit}
                units supported:
                K, KB, k or kb - kilobytes
                M, MB, m or mb - megabytes
                G, GB, g or gb - gigabytes
                T, TB, t or tb - terabytes
    Returns:
        number of bytes
        None; if input is incorrect
    """
    match = re.search('^([0-9]+)([a-zA-Z]{0,2})$', in_str)

    if not match:
        return None

    unit = match.group(2).upper()
    value = match.group(1)

    size_count = long(value)
    if unit in ['K', 'KB']:
        multiplier = long(1024)
    elif unit in ['M', 'MB']:
        multiplier = long(1024 * 1024)
    elif unit in ['G', 'GB']:
        multiplier = long(1024 * 1024 * 1024)
    elif unit in ['T', 'TB']:
        multiplier = long(1024 * 1024 * 1024 * 1024)
    elif unit == "":
        return size_count
    else:
        return None

    size_in_bytes = long(size_count * multiplier)
    return size_in_bytes


def get_list(json_object, parent_node_name, child_node_name=None):
    '''Returns a list of values from child_node_name

    If child_node is not given, then it will retrieve list from parent node
    '''
    if not json_object:
        return []

    return_list = []
    if isinstance(json_object[parent_node_name], list):
        for detail in json_object[parent_node_name]:
            if child_node_name:
                return_list.append(detail[child_node_name])
            else:
                return_list.append(detail)
    else:
        if child_node_name:
            return_list.append(json_object[parent_node_name][child_node_name])
        else:
            return_list.append(json_object[parent_node_name])

    return return_list


def get_node_value(json_object, parent_node_name, child_node_name=None):
    '''Returns value of given child_node

    If child_node is not given, then value of parent node is returned
    returns None: If json_object or parent_node is not given,
                  If child_node is not found under parent_node
    '''
    if not json_object:
        return None

    if not parent_node_name:
        return None

    detail = json_object[parent_node_name]
    if not child_node_name:
        return detail

    return_value = None

    if child_node_name in detail:
        return_value = detail[child_node_name]
    else:
        return_value = None

    return return_value


# This method defines the standard and consistent error message format
# for all CLI error messages.
#
# Use it for any error message to be formatted
'''
@operationType create, update, add, etc
@component storagesystem, filesystem, vpool, etc
@errorCode Error code from the API call
@errorMessage Detailed error message
'''


def format_err_msg_and_raise(operationType, component,
                             errorMessage, errorCode):
    formatedErrMsg = "Error: Failed to " + operationType + " " + component
    if errorMessage.startswith("\"\'") and errorMessage.endswith("\'\""):
        # stripping the first 2 and last 2 characters, which are quotes.
        errorMessage = errorMessage[2:len(errorMessage) - 2]

    formatedErrMsg = formatedErrMsg + "\nReason:" + errorMessage
    raise CoprHdError(errorCode, formatedErrMsg)

'''Terminate the script execution with status code

Ignoring the exit status code means the script execution completed successfully
exit_status_code = 0, means success, its a default behavior
exit_status_code = integer greater than zero, abnormal termination
'''


def exit_gracefully(exit_status_code):
    sys.exit(exit_status_code)


def search_by_tag(resourceSearchUri, ipAddr, port):
    '''Fetches the list of resources with a given tag

    Parameter resourceSearchUri : The tag based search uri
                              Example: '/block/volumes/search?tag=tagexample1'
    '''
    # check if the URI passed has both project and name parameters
    strUri = str(resourceSearchUri)
    if strUri.__contains__("search") and strUri.__contains__("?tag="):
        # Get the project URI

        (s, h) = service_json_request(
            ipAddr, port, "GET",
            resourceSearchUri, None)

        o = json_decode(s)
        if not o:
            return None

        resources = get_node_value(o, "resource")

        resource_uris = []
        for resource in resources:
            resource_uris.append(resource["id"])
        return resource_uris
    else:
        raise CoprHdError(CoprHdError.VALUE_ERR, "Search URI " + strUri +
                          " is not in the expected format, it should end" +
                          " with ?tag={0}")


# Timeout handler for synchronous operations
def timeout_handler():
    global IS_TASK_TIMEOUT
    IS_TASK_TIMEOUT = True


# Blocks the operation until the task is complete/error out/timeout
def block_until_complete(componentType,
                         resource_uri,
                         task_id,
                         ipAddr,
                         port,
                         synctimeout=0):
    global IS_TASK_TIMEOUT
    IS_TASK_TIMEOUT = False
    if synctimeout:
        t = Timer(synctimeout, timeout_handler)
    else:
        synctimeout = 300
        t = Timer(300, timeout_handler)
    t.start()
    while True:
        out = get_task_by_resourceuri_and_taskId(
            componentType, resource_uri, task_id, ipAddr, port)

        if out:
            if out["state"] == "ready":

                    # cancel the timer and return
                t.cancel()
                break

            # if the status of the task is 'error' then cancel the timer
            # and raise exception
            if out["state"] == "error":
                # cancel the timer
                t.cancel()
                if "service_error" in out and \
                        "details" in out["service_error"]:
                    error_message = out["service_error"]["details"]
                raise CoprHdError(CoprHdError.VALUE_ERR, "Task: " + task_id +
                                  " is failed with error: " + error_message)

        if IS_TASK_TIMEOUT:
            IS_TASK_TIMEOUT = False
            raise CoprHdError(CoprHdError.TIME_OUT,
                              "Task did not complete in %d secs." +
                              "Operation timed out. Task in CoprHD " +
                              "will continue")

    return


def get_task_by_resourceuri_and_taskId(componentType, resource_uri,
                                       task_id, ipAddr, port):
    '''Returns the single task details

    '''

    task_uri_constant = singletonURIHelperInstance.getUri(
        componentType, "task")
    (s, h) = service_json_request(
        ipAddr, port, "GET",
        task_uri_constant.format(resource_uri, task_id), None)
    if not s:
        return None
    o = json_decode(s)
    return o


class CoprHdError(Exception):

    '''Custom exception class used to report CLI logical errors

    Attributes:
        err_code - String error code
        err_text - String text
    '''
    SOS_FAILURE_ERR = 1
    CMD_LINE_ERR = 2
    HTTP_ERR = 3
    VALUE_ERR = 4
    NOT_FOUND_ERR = 1
    ENTRY_ALREADY_EXISTS_ERR = 5
    MAX_COUNT_REACHED = 6
    TIME_OUT = 7

    def __init__(self, err_code, err_text):
        self.err_code = err_code
        self.err_text = err_text

    def __str__(self):
        return repr(self.err_text)
