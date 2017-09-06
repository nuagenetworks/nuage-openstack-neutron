# Copyright 2016 NOKIA
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

import base64
import calendar
try:
    import httplib as httpclient      # python 2
except ImportError:
    import http.client as httpclient  # python 3
import json
import logging
import re
import socket
import ssl
import time

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants as plugin_constants
from nuage_neutron.plugins.common import nuage_models

from neutron._i18n import _
from neutron.db import api as db_api

LOG = logging.getLogger(__name__)

REST_SUCCESS_CODES = range(200, 207)
REST_UNAUTHORIZED = 401
REST_NOT_FOUND = 404
REST_CONFLICT = 409
REST_CONFLICT_ERR_CODE = REST_CONFLICT
REST_SERV_UNAVAILABLE_CODE = 503

REST_EXISTS_INTERNAL_ERR_CODE = '2510'
REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = '2039'
REST_VM_UUID_IN_USE_ERR_CODE = '2748'
REST_VLAN_EXISTS_ERR_CODE = '3316'
REST_VLAN_IN_USE_ERR_CODE = '7053'
REST_IFACE_EXISTS_ERR_CODE = '7006'
REST_ENT_PERMS_EXISTS_ERR_CODE = '4504'

# legacy - deprecated
CONFLICT_ERR_CODE = REST_CONFLICT
RES_NOT_FOUND = REST_NOT_FOUND
RES_CONFLICT = REST_CONFLICT
RES_EXISTS_INTERNAL_ERR_CODE = REST_EXISTS_INTERNAL_ERR_CODE
VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = \
    REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE

VSD_RESP_OBJ = 3

LIST_L2DOMAINS = re.compile('.*/l2domains(\?.*)?$')
LIST_SUBNETS = re.compile('.*/subnets(\?.*)?$')
GET_L2DOMAIN = re.compile('/l2domains/([0-9a-fA-F\-]+?)(\?.*)?$')
GET_SUBNET = re.compile('/subnets/([0-9a-fA-F\-]+?)(\?.*)?$')


class RESTProxyBaseException(Exception):
    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(RESTProxyBaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            if self.use_fatal_exceptions():
                raise
            else:
                super(RESTProxyBaseException, self).__init__(self.message)

    def __unicode__(self):
        return str(self.msg)

    def use_fatal_exceptions(self):
        return False


class RESTProxyError(RESTProxyBaseException):
    def __init__(self, message, error_code=None, vsd_code=None):
        self.code = 0
        if error_code:
            self.code = error_code
        self.vsd_code = vsd_code

        if message is None:
            message = "None"

        if self.code == REST_CONFLICT_ERR_CODE:
            self.message = (_('%s') % message)
        else:
            self.message = (_('Error in REST call to VSD: %s') % message)
        super(RESTProxyError, self).__init__()


class ResourceExistsException(RESTProxyError):
    def __init__(self, message):
        super(ResourceExistsException, self).__init__(
            message,
            REST_CONFLICT_ERR_CODE,
            vsd_code=REST_EXISTS_INTERNAL_ERR_CODE)

        super(RESTProxyError, self).__init__()


class ResourceNotFoundException(RESTProxyError):
    def __init__(self, message):
        super(ResourceNotFoundException, self).__init__(
            message,
            REST_NOT_FOUND)


class RESTProxyServer(object):

    def __init__(self, server, base_uri, serverssl,
                 serverauth, auth_resource,
                 organization, servertimeout=30,
                 max_retries=5):
        try:
            server_ip, port = server.split(":")
        except ValueError:
            server_ip = server
            port = None
        self.server = server_ip
        self.port = int(port) if port else None
        self.base_uri = base_uri
        self.serverssl = serverssl
        self.serverauth = serverauth
        self.auth_resource = auth_resource
        self.organization = organization
        self.timeout = servertimeout
        self.max_retries = max_retries
        self.auth = None
        self.success_codes = range(200, 207)
        self.api_count = 0

    @staticmethod
    def raise_rest_error(msg, exc=None, log_as_error=True):
        if log_as_error:
            LOG.error(_('RESTProxy: %s'), msg)
        else:
            LOG.debug(_('RESTProxy: %s'), msg)
        if exc:
            raise exc
        else:
            raise Exception(msg)

    @staticmethod
    def raise_error_response(response):
        try:
            errors = json.loads(response[3])
            log_as_error = False
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                log_as_error = True
                msg = 'VSD temporarily unavailable, ' + str(errors['errors'])
            else:
                msg = str(
                    errors['errors'][0]['descriptions'][0]['description'])

            if response[0] == REST_NOT_FOUND:
                e = ResourceNotFoundException(msg)
            else:
                vsd_code = str(errors.get('internalErrorCode'))
                e = RESTProxyError(msg, error_code=response[0],
                                   vsd_code=vsd_code)
            RESTProxyServer.raise_rest_error(msg, e, log_as_error)
        except (TypeError, ValueError):
            if response[3]:
                LOG.error('REST response from VSD: %s', response[3])
            msg = ("Cannot communicate with SDN controller. Please do not"
                   " perform any further operations and contact the"
                   " administrator.")
            RESTProxyServer.raise_rest_error(msg)

    def _rest_call(self, action, resource, data, extra_headers=None,
                   ignore_marked_for_deletion=False):
        if nuage_config.is_enabled(plugin_constants.DEBUG_API_STATS):
            self.api_count += 1
        uri = self.base_uri + resource
        body = json.dumps(data)
        headers = {'Content-type': 'application/json',
                   'X-Nuage-Organization': self.organization}
        if self.auth:
            headers['Authorization'] = self.auth
        if extra_headers:
            headers.update(extra_headers)

        if "X-Nuage-Filter" in headers:
            hdr = '[' + headers['X-Nuage-Filter'] + ']'
            LOG.debug('VSD_API REQ %s %s %s %s', action, uri, hdr, body)
        else:
            LOG.debug('VSD_API REQ %s %s %s', action, uri, body)

        ret = None
        for attempt in range(self.max_retries):
            try:
                conn = self._create_connection()
                conn.request(action, uri, body, headers)
                response = conn.getresponse()
                respstr = response.read()
                respdata = respstr

                LOG.debug('VSD_API RSP %s %s %s',
                          response.status,
                          response.reason,
                          respdata)
                if response.status in self.success_codes:
                    try:
                        respdata = json.loads(respstr)
                    except ValueError:
                        # response was not JSON, ignore the exception
                        pass
                    if (action.upper() == 'GET' and
                            not ignore_marked_for_deletion):
                        if (LIST_L2DOMAINS.match(resource) is not None or
                                LIST_SUBNETS.match(resource) is not None):
                            respdata = [
                                d for d in respdata if not self.is_marked(d)]
                        else:
                            match = GET_L2DOMAIN.match(resource)
                            if match is not None and respdata and \
                                    self.is_marked(respdata[0]):
                                return self._l2domain_not_found(match.group(1))
                            match = GET_SUBNET.match(resource)
                            if match is not None and respdata and \
                                    self.is_marked(respdata[0]):
                                return self._subnet_not_found(match.group(1))
                ret = (response.status, response.reason, respstr, respdata,
                       dict(response.getheaders()), headers['Authorization'])
            except (socket.timeout, socket.error) as e:
                LOG.error(_('ServerProxy: %(action)s failure, %(e)r'),
                          locals())
            else:
                conn.close()
                if response.status != REST_SERV_UNAVAILABLE_CODE:
                    return ret
            time.sleep(1)
            LOG.debug("Attempt %s of %s", attempt + 1, self.max_retries)
        LOG.debug('After %d retries VSD did not respond properly.',
                  self.max_retries)
        return ret or 0, None, None, None, None, headers['Authorization']

    def _create_connection(self):
        if self.serverssl:
            if hasattr(ssl, '_create_unverified_context'):
                # pylint: disable=no-member
                # pylint: disable=unexpected-keyword-arg
                conn = httpclient.HTTPSConnection(
                    self.server, self.port, timeout=self.timeout,
                    context=ssl._create_unverified_context())
                # pylint: enable=no-member
                # pylint: enable=unexpected-keyword-arg
            else:
                conn = httpclient.HTTPSConnection(
                    self.server, self.port, timeout=self.timeout)
        else:
            conn = httpclient.HTTPConnection(
                self.server, self.port, timeout=self.timeout)

        if conn is None:
            self.raise_rest_error(
                'Could not create HTTP(S)Connection object.')
        return conn

    @staticmethod
    def get_config_parameter_by_name(session, organization, user_name,
                                     param_name):
        return session.query(nuage_models.NuageConfig).filter_by(
            organization=organization,
            username=user_name,
            config_parameter=param_name).with_for_update().first()

    @staticmethod
    def add_config_parameter(session, organization, username,
                             parameter, value):
        config_parameter = nuage_models.NuageConfig(organization=organization,
                                                    username=username,
                                                    config_parameter=parameter,
                                                    config_value=value)
        session.merge(config_parameter)

    def create_or_update_nuage_config_param(self, session, organization,
                                            user_name, param_name,
                                            param_value):
        with session.begin(subtransactions=True):
            config_mapping = self.get_config_parameter_by_name(session,
                                                               organization,
                                                               user_name,
                                                               param_name)
            if (config_mapping and
                    config_mapping['config_value'] != param_value):
                config_mapping.update({'config_value': param_value})
            elif not config_mapping:
                self.add_config_parameter(session, organization, user_name,
                                          param_name,
                                          param_value)

    @staticmethod
    def delete_config_parameter(session, config_parameter):
        session.delete(config_parameter)

    def compute_sleep_time(self, api_key_info):
        # Assuming it's always going be in GMT
        response_headers = api_key_info[4]
        api_key_data = api_key_info[3][0]
        if response_headers and api_key_data:
            current_time_on_vsd = int(calendar.timegm(time.strptime(
                response_headers['date'].rstrip(' GMT'),
                "%a, %d %b %Y %H:%M:%S")))
            # Convert from milli seconds to seconds
            api_expiry_time = api_key_data['APIKeyExpiry'] / 1000
            response = self.get('/systemconfigs', required=True)
            if response[0]:
                renewal_before = response[0]['APIKeyRenewalInterval']
                time_to_sleep = (
                    api_expiry_time - current_time_on_vsd - renewal_before)
                time_to_sleep = time_to_sleep if time_to_sleep > 0 else 1
                return time_to_sleep

        # Sleep for 1 second and compute value for time to sleep.
        return 1

    def generate_nuage_auth(self, auth_token=None):
        data = ''
        encoded_auth = base64.encodestring(self.serverauth).strip()
        self.auth = 'Basic ' + encoded_auth
        resp = self._rest_call('GET', self.auth_resource, data)
        if resp[0] == 0:
            self.raise_rest_error(
                'Could not establish a connection with the VSD. '
                'Please check VSD URI path in plugin config and '
                'verify IP connectivity.')
        if resp[0] in self.success_codes and resp[3][0].get('APIKey'):
            uname = self.serverauth.split(':')[0]
            if not auth_token:
                session = db_api.get_session()
                self.create_or_update_nuage_config_param(
                    session, self.organization, uname, 'auth_token',
                    resp[3][0]['APIKey'])
            else:
                auth_token.update({'config_value': resp[3][0]['APIKey']})
            new_uname_pass = uname + ':' + resp[3][0]['APIKey']
            auth = 'Basic ' + base64.encodestring(new_uname_pass).strip()
            self.auth = auth
            LOG.debug("[RESTProxy] New auth-token received %s", auth)
            return resp
        else:
            self.raise_rest_error(
                'Could not authenticate with the VSD. '
                'Please check the credentials in the plugin config.')

    def rest_call(self, action, resource, data, extra_headers=None,
                  ignore_marked_for_deletion=False):
        response = self._rest_call(
            action, resource, data, extra_headers=extra_headers,
            ignore_marked_for_deletion=ignore_marked_for_deletion)
        '''
        If at all authentication expires with VSD, re-authenticate.
        '''
        if response[0] == REST_UNAUTHORIZED and response[1] == 'Unauthorized':
            LOG.debug(_('RESTProxy: authentication expired, '
                        're-authenticating.'))
            session = db_api.get_session()
            with session.begin(subtransactions=True):
                auth_token = self.get_config_parameter_by_name(
                    session,
                    self.organization,
                    self.serverauth.split(':')[0],
                    'auth_token')
                in_db_uname_pass = (auth_token['username'] + ':' +
                                    auth_token['config_value'])
                in_db_auth = 'Basic ' + base64.encodestring(
                    in_db_uname_pass).strip()
                LOG.debug("Auth_from_DB: %s", in_db_auth)
                LOG.debug("Auth_from_request: %s", response[5])
                if in_db_auth != response[5]:
                    self.auth = in_db_auth
                    return self.rest_call(action, resource, data,
                                          extra_headers=extra_headers)
                else:
                    self.generate_nuage_auth(auth_token)
            return self._rest_call(action, resource, data,
                                   extra_headers=extra_headers)
        return response

    def get(self, resource, data='', extra_headers=None, required=False):
        response = self.rest_call('GET', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_NOT_FOUND and not required:
            return ''
        else:
            self.raise_error_response(response)

    def _get_ignore_marked_for_deletion(self, resource, data='',
                                        extra_headers=None, required=False):
        response = self.rest_call(
            'GET', resource, data, extra_headers=extra_headers,
            ignore_marked_for_deletion=True)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_NOT_FOUND and not required:
            return ''
        else:
            self.raise_error_response(response)

    @staticmethod
    def retrieve_by_external_id(restproxy, resource, data):
        if not data.get('externalID'):
            return None
        headers = {'X-NUAGE-FilterType': "predicate",
                   'X-Nuage-Filter':
                       "externalID IS '%s'" % data.get('externalID')}
        return restproxy.get(resource, extra_headers=headers)

    @staticmethod
    def retrieve_by_name(restproxy, resource, data):
        if not data.get('name'):
            return None
        headers = {'X-NUAGE-FilterType': "predicate",
                   'X-Nuage-Filter': "name IS '%s'" % data.get('name')}
        return restproxy.get(resource, extra_headers=headers)

    def post(self, resource, data, extra_headers=None,
             on_res_exists=retrieve_by_external_id.__func__,
             ignore_err_codes=None):
        if ignore_err_codes is None:
            ignore_err_codes = [REST_EXISTS_INTERNAL_ERR_CODE]
        response = self.rest_call('POST', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_UNAUTHORIZED:
            # probably this is a POST of VM but user is not in CMS group
            self.raise_rest_error(
                'Unauthorized to this VSD API. '
                'Please check the user credentials in plugin config belong '
                'to CMS group in VSD.')
        elif response[0] == REST_CONFLICT_ERR_CODE:
            # Under heavy load, vsd responses may get lost. We must try find
            # the resource else it's stuck in VSD.
            errors = json.loads(response[3])
            if (str(errors.get('internalErrorCode')) in ignore_err_codes):
                get_response = None
                if on_res_exists:
                    get_response = on_res_exists(self, resource, data)
                if not get_response:
                    errors = json.loads(response[3])
                    msg = str(errors['errors'][0]['descriptions'][0]
                              ['description'])
                    self.raise_rest_error(msg, ResourceExistsException(msg))
                return get_response
        self.raise_error_response(response)

    def put(self, resource, data, extra_headers=None):
        response = self.rest_call('PUT', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return
        else:
            errors = json.loads(response[3])
            vsd_code = str(errors.get('internalErrorCode'))
            if vsd_code == REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE:
                return
            self.raise_error_response(response)

    def delete(self, resource, data='', extra_headers=None, required=False):
        response = self.rest_call('DELETE', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_NOT_FOUND and not required:
            return None
        else:
            self.raise_error_response(response)

    def _l2domain_not_found(self, id):
        return self._resource_not_found('l2domain', id)

    def _subnet_not_found(self, id):
        return self._resource_not_found('subnet', id)

    def _resource_not_found(self, resource, id):
        """Replicate VSD 404 response"""
        vsd_response = (
            '{"title": "%(resource)s not found",'
            '"errors": [{"property": "","'
            'descriptions": [{"title": "%(resource)s not found",'
            '"description": "Cannot find %(resource)s with ID %(id)s"}]}],'
            '"description": "Cannot find %(resource)s with ID %(id)s"}'
            % {'resource': resource,
               'id': id})
        return REST_NOT_FOUND, 'Not Found', vsd_response, vsd_response

    @staticmethod
    def is_marked(vsd_object):
        return vsd_object.get('name', '').endswith('_MARKED_FOR_DELETION')
