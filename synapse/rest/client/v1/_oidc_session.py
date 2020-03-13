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
import time
from typing import Optional

import attr

SESSION_COOKIE_NAME = b"synapse_oidc_session"

logger = logging.getLogger(__name__)


@attr.s
class OIDCSession:
    """Data we track about OIDC sessions"""

    # where to redirect the client back to
    client_redirect_url = attr.ib(type=str)

    # expiry time for the session, in milliseconds
    expiry_time_ms = attr.ib(type=int)

    # state used in authorization flow
    state = attr.ib(type=str)


# a map from session id to session data
oidc_sessions = {}  # type: dict[str, OIDCSession]


def expire_old_sessions(gettime=time.time):
    """Delete any sessions which have passed their expiry_time"""
    to_expire = []
    now = int(gettime() * 1000)

    for session_id, session in oidc_sessions.items():
        if session.expiry_time_ms <= now:
            to_expire.append(session_id)

    for session_id in to_expire:
        logger.info("Expiring OIDC session %s", session_id)
        del oidc_sessions[session_id]


def get_mapping_session(session_id: str) -> Optional[OIDCSession]:
    """Look up the given session id, first expiring any old sessions"""
    expire_old_sessions()
    return oidc_sessions.get(session_id, None)
