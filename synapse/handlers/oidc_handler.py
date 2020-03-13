# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import uuid
from urllib.parse import urlencode

import attr
from synapse.util.async_helpers import Linearizer

logger = logging.getLogger(__name__)


@attr.s
class OIDCSessionData:
    """Data we track about OIDC sessions"""

    # where to redirect the client back to
    client_redirect_url = attr.ib(type=str)

    # time the session was created, in milliseconds
    creation_time = attr.ib()

    # state used in authorization flow
    state = attr.ib(type=str)


class OIDCHandler:
    def __init__(self, hs):
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()

        self._clock = hs.get_clock()
        self._datastore = hs.get_datastore()
        self._hostname = hs.hostname
        self._server_baseurl = hs.config.public_baseurl
        self._authorize_url = hs.config.oidc_provider_authorize_url
        self._client_id = hs.config.oidc_provider_client_id
        self._session_validity_ms = hs.config.oidc_session_validity_ms
        self._state = str(uuid.uuid4())

        # identifier for the external_ids table
        self._auth_provider_id = "oidc"

        # a map from oidc session id to OIDCSessionData object
        self._outstanding_requests_dict = {}

        # a lock on the mappings
        self._mapping_lock = Linearizer(name="oidc_mapping", clock=self._clock)

    def handle_redirect_request(self, request, client_redirect_url):
        """Handle an incoming request to /login/sso/redirect

        Args:
            request (Request): Request object
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            bytes: URL to redirect to
        """
        session_id = str(uuid.uuid4())
        now = self._clock.time_msec()
        self._outstanding_requests_dict[session_id] = OIDCSessionData(
            client_redirect_url=client_redirect_url.decode("utf-8"),
            creation_time=now,
            state=self._state,
        )
        request.addCookie("synapse_oidc_session", session_id, path="/", secure=True)

        params = {
            b"response_type": b"code",
            b"scope": b"openid preferred_username",
            b"client_id": b"%s" % self._client_id.encode("ascii"),
            b"state": b"%s" % self._state.encode("ascii"),
            b"redirect_uri": b"%s_synapse/oidc/authorize_response" % self._server_baseurl.encode("ascii"),
        }
        params = urlencode(params).encode("ascii")
        return b"%s?%s" % (self._authorize_url, params)

    async def handle_authorization_response(self, request):
        """Handle an incoming request to /_synapse/oidc/authorize_response

        Args:
            request (SynapseRequest): the incoming request from the browser.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """
        # TODO get code and such from request
        # expire outstanding sessions before parse_authn_request_response checks
        # the dict.
        self.expire_sessions()

    def expire_sessions(self):
        expire_before = self._clock.time_msec() - self._session_validity_ms
        to_expire = set()
        for reqid, data in self._outstanding_requests_dict.items():
            if data.creation_time < expire_before:
                to_expire.add(reqid)
        for reqid in to_expire:
            logger.debug("Expiring session id %s", reqid)
            del self._outstanding_requests_dict[reqid]
