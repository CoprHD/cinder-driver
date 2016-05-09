#!/usr/bin/python

# Copyright (c) 2016 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
'''
Contains some commonly used utility methods
'''
import os
import stat
import json
import re
import datetime
import sys
import socket
import base64
import requests
from requests.exceptions import SSLError
from requests.exceptions import ConnectionError
from requests.exceptions import TooManyRedirects
from requests.exceptions import Timeout
import cookielib
import xml.dom.minidom
import getpass
from xml.etree import ElementTree
from threading import Timer

from urihelper import singletonURIHelperInstance

PROD_NAME = 'storageos'
TENANT_PROVIDER = 'urn:vipr:TenantOrg:provider:'

SWIFT_AUTH_TOKEN = 'X-Auth-Token'

TIMEOUT_SEC = 20  # 20 SECONDS
OBJCTRL_INSECURE_PORT = '9010'
OBJCTRL_PORT = '4443'
IS_TASK_TIMEOUT = False


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
    '''
    Used to decode the JSON encoded response
    '''
    o = ""
    try:
        o = json.loads(rsp, object_hook=_decode_dict)
    except ValueError:
        raise SOSError(SOSError.VALUE_ERR,
                       "Failed to recognize JSON payload:\n[" + rsp + "]")
    return o


def json_encode(name, value):
    '''
    Used to encode any attribute in JSON format
    '''

    body = json.dumps({name: value})
    return body


def service_json_request(ip_addr, port, http_method, uri, body, token=None,
                         xml=False, contenttype='application/json',
                         filename=None, customheaders=None):
    '''
    Used to make an HTTP request and get the response.
    The message body is encoded in JSON format.
    Parameters:
        ip_addr: IP address or host name of the server
        port: port number of the server on which it
            is listening to HTTP requests
        http_method: one of GET, POST, PUT, DELETE
        uri: the request URI
        body: the request payload
    Returns:
        a tuple of two elements: (response body, response headers)
    Throws: SOSError in case of HTTP errors with err_code 3
    '''
    global COOKIE

    SEC_AUTHTOKEN_HEADER = 'X-SDS-AUTH-TOKEN'

    if (xml):
        headers = {'Content-Type': contenttype,
                   'ACCEPT': 'application/xml, application/octet-stream',
                   'X-EMC-REST-CLIENT': 'TRUE'}
    else:
        headers = {'Content-Type': contenttype,
                   'ACCEPT': 'application/json, application/octet-stream',
                   'X-EMC-REST-CLIENT': 'TRUE'}

    if(customheaders):
        headers.update(customheaders)

    if (token):
        if ('?' in uri):
            uri += '&requestToken=' + token
        else:
            uri += '?requestToken=' + token

    try:

        cookiefile = COOKIE
        form_cookiefile = None
        if (cookiefile is None):
            #install_dir = getenv('VIPR_CLI_INSTALL_DIR')
            install_dir = "."
            if (install_dir is None):
                raise SOSError(SOSError.NOT_FOUND_ERR,
                               "VIPR_CLI_INSTALL_DIR is not set.\n")
            if sys.platform.startswith('linux'):
                parentshellpid = os.getppid()
                if (parentshellpid is not None):
                    form_cookiefile = install_dir + '/cookie/' + \
                        str(parentshellpid)
                else:
                    form_cookiefile = install_dir + '/cookie/cookiefile'
            elif sys.platform.startswith('win'):
                form_cookiefile = install_dir + '\\cookie\\cookiefile'
            else:
                form_cookiefile = install_dir + '/cookie/cookiefile'
        if (form_cookiefile):
            cookiefile = form_cookiefile
            if (not os.path.exists(cookiefile)):
                raise SOSError(SOSError.NOT_FOUND_ERR,
                               cookiefile + " : Cookie not found :" +
                               " Please authenticate again")
            fd = open(cookiefile, 'r')
            if (fd):
                fd_content = fd.readline().rstrip()
                if(fd_content):
                    cookiefile = fd_content
                else:
                    raise SOSError(SOSError.NOT_FOUND_ERR,
                                   cookiefile + " : Failed to retrive" +
                                   " the cookie file")
            else:
                raise SOSError(SOSError.NOT_FOUND_ERR,
                               cookiefile + " : read failure\n")
        # cli support for api version
        protocol = "https://"
        if(str(port) == '8080'):
            protocol = "http://"
        url = protocol + ip_addr + ":" + str(port) + uri

        cookiejar = cookielib.LWPCookieJar()
        if (cookiefile):
            if (not os.path.exists(cookiefile)):
                raise SOSError(SOSError.NOT_FOUND_ERR, cookiefile + " : " +
                               "Cookie not found : Please authenticate again")
            if (not os.path.isfile(cookiefile)):
                raise SOSError(SOSError.NOT_FOUND_ERR,
                               cookiefile + " : Not a cookie file")
            # cookiejar.load(cookiefile, ignore_discard=True,
            # ignore_expires=True)
            tokenfile = open(cookiefile)
            token = tokenfile.read()
            tokenfile.close()
        else:
            raise SOSError(SOSError.NOT_FOUND_ERR,
                           cookiefile + " : Cookie file not found")

        headers[SEC_AUTHTOKEN_HEADER] = token

        if (http_method == 'GET'):
            '''when the GET request is specified with a filename, we write
               the contents of the GET request to the filename. This option
               generally is used when the contents to be returned are large.
               So, rather than getting all the data at once we Use
               stream=True for the purpose of streaming. Stream = True
               means we can stream data'''
            if(filename):
                response = requests.get(url, stream=True, headers=headers,
                                        verify=False, cookies=cookiejar)

            else:
                response = requests.get(url, headers=headers, verify=False,
                                        cookies=cookiejar)

            if(filename):
                try:
                    with open(filename, 'wb') as fp:
                        while(True):
                            chunk = response.raw.read(100)

                            if not chunk:
                                break
                            fp.write(chunk)
                except IOError as e:
                    raise SOSError(e.errno, e.strerror)

        elif (http_method == 'POST'):
            if(filename):
                with open(filename, "rb") as f:
                    response = requests.post(url, data=f, headers=headers,
                                             verify=False, cookies=cookiejar)
            else:
                response = requests.post(url, data=body, headers=headers,
                                         verify=False, cookies=cookiejar)
        elif (http_method == 'PUT'):
            response = requests.put(url, data=body, headers=headers,
                                    verify=False, cookies=cookiejar)
        elif (http_method == 'DELETE'):

            response = requests.delete(url, headers=headers, verify=False,
                                       cookies=cookiejar)
        else:
            raise SOSError(SOSError.HTTP_ERR,
                           "Unknown/Unsupported HTTP method: " + http_method)

        if((response.status_code == requests.codes['ok']) or
           (response.status_code == 202)):
            return (response.text, response.headers)
        else:
            error_msg = None
            if(response.status_code == 500):
                responseText = json_decode(response.text)
                errorDetails = ""
                if('details' in responseText):
                    errorDetails = responseText['details']
                error_msg = "ViPR internal server error. Error details: " + \
                    errorDetails
            elif(response.status_code == 401):
                error_msg = "Access forbidden: Authentication required"
            elif(response.status_code == 403):
                error_msg = ""
                errorDetails = ""
                errorDescription = ""

                responseText = json_decode(response.text)

                if('details' in responseText):
                    errorDetails = responseText['details']
                    error_msg = error_msg + "Error details: " + errorDetails
                elif('description' in responseText):
                    errorDescription = responseText['description']
                    error_msg = error_msg + "Error description: " + \
                        errorDescription
                else:
                    error_msg = "Access forbidden: You don't have" + \
                        " sufficient privileges to perform this operation"

            elif(response.status_code == 404):
                error_msg = "Requested resource not found"
            elif(response.status_code == 405):
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
                    error_msg = "Service temporarily unavailable: The server" + \
                                " is temporarily unable to service your request"
            else:
                error_msg = response.text
                if isinstance(error_msg, unicode):
                    error_msg = error_msg.encode('utf-8')
            raise SOSError(SOSError.HTTP_ERR, "HTTP code: " +
                           str(response.status_code) +
                           ", " + response.reason + " [" + error_msg + "]")

    except (SOSError, socket.error, SSLError,
            ConnectionError, TooManyRedirects, Timeout) as e:
        raise SOSError(SOSError.HTTP_ERR, str(e))
    # TODO : Either following exception should have proper message or IOError
    # should just be combined with the above statement
    except IOError as e:
        raise SOSError(SOSError.HTTP_ERR, str(e))


def is_uri(name):
    '''
    Checks whether the name is a UUID or not
    Returns:
        True if name is UUID, False otherwise
    '''
    try:
        (urn, prod, trailer) = name.split(':', 2)
        return (urn == 'urn' and prod == PROD_NAME)
    except:
        return False


def get_viprcli_version():
    try:
        filename = os.path.abspath(os.path.dirname(__file__))
        filename = os.path.join(filename, "ver.txt")
        verfile = open(filename, 'r')
        line = verfile.readline().strip("\r\n")
        verfile.close()
        return line
    except IOError as e:
        raise SOSError(SOSError.NOT_FOUND_ERR, str(e))


def format_json_object(obj):
    '''
    Formats JSON object to make it readable by proper indentation
    Parameters:
        obj - JSON object
    Returns:
        a string of  formatted JSON object
    '''
    return json.dumps(obj, sort_keys=True, indent=3)


def get_parent_child_from_xpath(name):
    '''
    Returns the parent and child elements from XPath
    '''
    if('/' in name):
        (pname, label) = name.rsplit('/', 1)
    else:
        pname = None
        label = name
    return (pname, label)


def to_bytes(in_str):
    """
    Converts a size to bytes
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
    if (unit in ['K', 'KB']):
        multiplier = long(1024)
    elif (unit in ['M', 'MB']):
        multiplier = long(1024 * 1024)
    elif (unit in ['G', 'GB']):
        multiplier = long(1024 * 1024 * 1024)
    elif (unit in ['T', 'TB']):
        multiplier = long(1024 * 1024 * 1024 * 1024)
    elif (unit == ""):
        return size_count
    else:
        return None

    size_in_bytes = long(size_count * multiplier)
    return size_in_bytes


def get_list(json_object, parent_node_name, child_node_name=None):
    '''
    Returns a list of values from child_node_name
    If child_node is not given, then it will retrieve list from parent node
    '''
    if(not json_object):
        return []

    return_list = []
    if isinstance(json_object[parent_node_name], list):
        for detail in json_object[parent_node_name]:
            if(child_node_name):
                return_list.append(detail[child_node_name])
            else:
                return_list.append(detail)
    else:
        if(child_node_name):
            return_list.append(json_object[parent_node_name][child_node_name])
        else:
            return_list.append(json_object[parent_node_name])

    return return_list


def get_node_value(json_object, parent_node_name, child_node_name=None):
    '''
    Returns value of given child_node. If child_node is not given, then value
    of parent node is returned.
    returns None: If json_object or parent_node is not given,
                  If child_node is not found under parent_node
    '''
    if(not json_object):
        return None

    if(not parent_node_name):
        return None

    detail = json_object[parent_node_name]
    if(not child_node_name):
        return detail

    return_value = None

    if(child_node_name in detail):
        return_value = detail[child_node_name]
    else:
        return_value = None

    return return_value


def show_by_href(ipAddr, port, href):
    '''
    This function will get the href of object and display the details
    of the same
    '''
    link = href['link']
    hrefuri = link['href']
    # we need keep except to over exception from appliance,
    # later we can take off
    try:
        (s, h) = service_json_request(ipAddr, port, "GET",
                                      hrefuri, None, None)
        o = json_decode(s)
        if(o['inactive']):
            return None
        return o
    except:
        pass
    return None


def create_file(file_path):
    '''
    Create a file in the specified path.
    If the file_path is not an absolute pathname, create the file from the
    current working directory.
    raise exception : Incase of any failures.
    returns True: Incase of successful creation of file
    '''
    fd = None
    try:
        if (file_path):
            if (os.path.exists(file_path)):
                if (os.path.isfile(file_path)):
                    return True
                else:
                    raise SOSError(SOSError.NOT_FOUND_ERR,
                                   file_path + ": Not a regular file")
            else:
                dir = os.path.dirname(file_path)
                if (dir and not os.path.exists(dir)):
                    os.makedirs(dir)
            fd = os.open(file_path, os.O_RDWR | os.O_CREAT,
                         stat.S_IREAD | stat.S_IWRITE |
                         stat.S_IRGRP | stat.S_IROTH)

    except OSError as e:
        raise e
    except IOError as e:
        raise e
    finally:
        if(fd):
            os.close(fd)
    return True

'''
Prompt the user to get the confirmation
action could be "restart service", "reboot node", "poweroff cluster" etc
'''

def ask_continue(action):
    print("Do you really want to " + action + "(y/n)?:")
    response = sys.stdin.readline().rstrip()

    while(str(response) != "y" and str(response) != "n"):
        response = ask_continue(action)

    return response


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
    if(errorMessage.startswith("\"\'") and errorMessage.endswith("\'\"")):
        # stripping the first 2 and last 2 characters, which are quotes.
        errorMessage = errorMessage[2:len(errorMessage) - 2]

    formatedErrMsg = formatedErrMsg + "\nReason:" + errorMessage
    raise SOSError(errorCode, formatedErrMsg)

'''
Terminate the script execution with status code.
Ignoring the exit status code means the script execution completed successfully
exit_status_code = 0, means success, its a default behavior
exit_status_code = integer greater than zero, abnormal termination
'''


def exit_gracefully(exit_status_code):
    sys.exit(exit_status_code)


'''
Fetches the list of resources with a given tag
Parameter resourceSearchUri : The tag based search uri.
                              Example: '/block/volumes/search?tag=tagexample1'
'''


def search_by_tag(resourceSearchUri, ipAddr, port):
    # check if the URI passed has both project and name parameters
    strUri = str(resourceSearchUri)
    if(strUri.__contains__("search") and strUri.__contains__("?tag=")):
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
        raise SOSError(SOSError.VALUE_ERR, "Search URI " + strUri +
                       " is not in the expected format, it should end" +
                       " with ?tag={0}")


# Timeout handler for synchronous operations
def timeout_handler():
    global IS_TASK_TIMEOUT
    IS_TASK_TIMEOUT = True


# Blocks the operation until the task is complete/error out/timeout
def block_until_complete(componentType, resource_uri, task_id, ipAddr, port, synctimeout=0):
    global IS_TASK_TIMEOUT
    IS_TASK_TIMEOUT = False
    if synctimeout:
        t = Timer(synctimeout, timeout_handler)
    else:
        synctimeout = 300
        t = Timer(300, timeout_handler)
    t.start()
    while(True):
        out = get_task_by_resourceuri_and_taskId(
            componentType, resource_uri, task_id, ipAddr, port)

        if(out):
            if(out["state"] == "ready"):

                    # cancel the timer and return
                t.cancel()
                break

            # if the status of the task is 'error' then cancel the timer
            # and raise exception
            if(out["state"] == "error"):
                # cancel the timer
                t.cancel()
                error_message = "Please see logs for more details"
                if("service_error" in out and
                   "details" in out["service_error"]):
                    error_message = out["service_error"]["details"]
                raise SOSError(SOSError.VALUE_ERR, "Task: " + task_id +
                               " is failed with error: " + error_message)

        if(IS_TASK_TIMEOUT):
            print "Task did not complete in %d secs. Task still in progress. Please check the logs for task status" % synctimeout
            IS_TASK_TIMEOUT = False
            break
    return


'''
Returns the single task details for a given resource and its associated task
parameter task_uri_constant : The URI constant for the task
'''


def get_task_by_resourceuri_and_taskId(componentType, resource_uri,
                                       task_id, ipAddr, port):

    task_uri_constant = singletonURIHelperInstance.getUri(
        componentType, "task")
    (s, h) = service_json_request(
        ipAddr, port, "GET",
        task_uri_constant.format(resource_uri, task_id), None)
    if (not s):
        return None
    o = json_decode(s)
    return o


class SOSError(Exception):

    '''
    Custom exception class used to report CLI logical errors
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

    def __init__(self, err_code, err_text):
        self.err_code = err_code
        self.err_text = err_text

    def __str__(self):
        return repr(self.err_text)
