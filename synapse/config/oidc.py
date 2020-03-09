# -*- coding: utf-8 -*-
# Copyright 2020 Matrix Foundation
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

from ._base import Config, ConfigError


class OIDCConfig(Config):
    """OIDC (OpenID Connect) Configuration
    """
    section = "oidc"

    # noinspection PyAttributeOutsideInit,PyUnusedLocal
    def read_config(self, config, **kwargs):
        oidc_config = config.get("oidc", {})
        self.oidc_enabled = oidc_config.get("enabled", False)
        if not self.oidc_enabled:
            return
        provider = oidc_config.get("provider", {})
        required_provider_values = ("client_id", "base_url", "authorize_path", "token_path", "userinfo_path")
        missing_values = [value for value in required_provider_values if provider.get(value) is None]
        if missing_values:
            raise ConfigError(
                "Config section 'oidc' is enabled but the 'provider' object is missing the following keys: %s." %
                ", ".join(missing_values),
            )
        base_url = provider.get("base_url").rstrip("/")
        if not base_url.startswith("https://"):
            raise ConfigError("Config item 'oidc.provider.base_url' should start with 'https://'.")
        if not all((
            provider.get("authorize_path").startswith("/"),
            provider.get("token_path").startswith("/"),
            provider.get("userinfo_path").startswith("/"),
        )):
            raise ConfigError("Config item 'oidc.provider' path values should start with a slash.")
        self.oidc_provider_authorize_url = "%s%s" % (base_url, provider.get("authorize_path"))
        self.oidc_provider_token_url = "%s%s" % (base_url, provider.get("token_path"))
        self.oidc_provider_userinfo_url = "%s%s" % (base_url, provider.get("userinfo_path"))
        self.oidc_provider_client_id = provider.get("client_id")

    # noinspection PyUnusedLocal
    @staticmethod
    def generate_config_section(config_dir_path, server_name, **kwargs):
        return """
        # Enable OpenID Connect for registration and login.
        #
        #oidc:
        #  enabled: true
        #  provider:
        #    client_id: "client_id_here"
        #    base_url: "https://openid.example.com"
        #    authorize_path: "/authorize"
        #    userinfo_path: "/userinfo"
        #    token_path: "/token"
        """
