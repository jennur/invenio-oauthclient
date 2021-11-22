# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2020 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Pre-configured remote application for enabling sign in/up with CERN.

1. Edit your configuration and add:

   .. code-block:: python

       import copy

       from invenio_oauthclient.contrib import owncloud

       OAUTH_REMOTE_REST_APP = copy.deepcopy(owncloud.REMOTE_REST_APP)
       # update any params if needed
       OAUTH_REMOTE_REST_APP["params"].update({})

       OAUTHCLIENT_REMOTE_APPS = dict(
           owncloud=OAUTH_REMOTE_REST_APP,
       )
       OAUTHCLIENT_REST_REMOTE_APPS = dict(
           owncloud=OAUTH_REMOTE_REST_APP,
       )
       OWNCLOUD_CREDENTIALS = dict(
           consumer_key="changeme",
           consumer_secret="changeme",
       )
2. Register a new application with CERN OPENID visiting the page
   ``https://application-portal.web.cern.ch/``. When registering the
   application ensure that the *Redirect URI* points to:
   ``http://localhost:5000/api/oauth/authorized/owncloud/``, if you have
   used the rest oauth application, or
   ``http://localhost:5000/oauth/authorized/owncloud/`` (note, CERN
   does not allow localhost to be used, thus you need to follow the CERN OAUTH
   section in the common recipes in
   ``https://digital-repositories.web.cern.ch/digital-repositories``.
3. Grab the *Client ID* and *Client Secret* after registering the application
   and add them to your instance configuration (``invenio.cfg``):
   .. code-block:: python
       OWNCLOUD_CREDENTIALS = dict(
           consumer_key="<CLIENT ID>",
           consumer_secret="<CLIENT SECRET>",
       )
4. Now login using CERN OAuth:
   - http://localhost:5000/oauth/login/owncloud/ , if you configure the UI oauth
     application.
   - http://localhost:5000/api/oauth/login/owncloud/ , if you configure the API
     oauth application.
5. Also, you should see CERN listed under Linked accounts:
   http://localhost:5000/account/settings/linkedaccounts/
By default the CERN module will try first look if a link already exists
between a CERN account and a user. If no link is found, the user is asked
to provide an email address to sign-up.
In templates you can add a sign in/up link:
.. code-block:: jinja
    <a href="{{ url_for("invenio_oauthclient.login",
      remote_app="owncloud") }}">
      Sign in with OwnCloud
    </a>
"""

from datetime import date, datetime, timedelta

from flask import Blueprint, current_app, flash, g, redirect, session, url_for
from flask_babelex import gettext as _
from flask_login import current_user
from invenio_db import db

from invenio_oauthclient.contrib.settings import OAuthSettingsHelper
from invenio_oauthclient.errors import OAuthResponseError
from invenio_oauthclient.handlers.utils import \
    require_more_than_one_external_account, token_delete
from invenio_oauthclient.models import RemoteAccount, RemoteToken, UserIdentity
from invenio_oauthclient.proxies import current_oauthclient
from invenio_oauthclient.utils import oauth_link_external_id, oauth_unlink_external_id


class OwnCloudOAuthSettingsHelper(OAuthSettingsHelper):
    """Default configuration for OwnCloud OAuth provider."""

    external_method = "owncloud"

    def __init__(self, title=None, description=None, base_url=None,
                 app_key=None, precedence_mask=None):
        """Constructor."""
        super().__init__(
            title or "OwnCloud",
            description or "Share files and folders, easy and secure",
            base_url or "https://localhost:9200/",
            app_key or "OWNCLOUD_APP_CREDENTIALS",
            request_token_params={'scope': 'openid profile email offline_access'},
            access_token_url="https://localhost:9200/konnect/v1/token",
            authorize_url="https://localhost:9200/signin/v1/identifier/_/authorize",
            content_type="application/json",
            precedence_mask=precedence_mask,
        )

    def get_handlers(self):
        """Return OwnCloud auth handlers."""
        return dict(
            authorized_handler="invenio_oauthclient.handlers"
                           ":authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.owncloud"
                            ":disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.owncloud:account_info",
                setup="invenio_oauthclient.contrib.owncloud:account_setup",
                view="invenio_oauthclient.handlers:signup_handler",
            ),
        )

    def get_rest_handlers(self):
        """Return OwnCloud auth REST handlers."""
        return dict(
            authorized_handler="invenio_oauthclient.handlers.rest"
                           ":authorized_signup_handler",
            disconnect_handler="invenio_oauthclient.contrib.owncloud"
                            ":disconnect_handler",
            signup_handler=dict(
                info="invenio_oauthclient.contrib.owncloud:account_info_rest",
                setup="invenio_oauthclient.contrib.owncloud:account_setup",
                view="invenio_oauthclient.handlers.rest:signup_handler",
            ),
            response_handler=(
                "invenio_oauthclient.handlers.rest:default_remote_response_handler"
            ),
            authorized_redirect_url="/",
            disconnect_redirect_url="/",
            signup_redirect_url="/",
            error_redirect_url="/",
            )

    @property
    def user_info_url(self):
        """Return the URL to fetch user info."""
        return f"{self.base_url}konnect/v1/userinfo"

_owncloud_app = OwnCloudOAuthSettingsHelper()

BASE_APP = _owncloud_app.base_app

REMOTE_APP = _owncloud_app.remote_app
"""OwnCloud remote application configuration."""

REMOTE_REST_APP = _owncloud_app.remote_rest_app
"""OwnCloud remote rest application configuration."""


def get_dict_from_response(response):
    """Check for errors in the response and return the resulting JSON."""
    if getattr(response, '_resp') and response._resp.code > 400:
        raise OAuthResponseError(
                'Application mis-configuration in OwnCloud', None, response
            )

    return response.data


def get_user_info(remote):
    """Get user information from OwnCloud."""
    response = remote.get(_owncloud_app.user_info_url)
    user_info = get_dict_from_response(response)
    response.data['username'] = response.data['preferred_username']
    if '@' in response.data['username']:
        user_info['username'], _ = response.data['username'].split('@')
    return user_info


def account_info(remote, resp):
    """Retrieve remote account information used to find local user.

    It returns a dictionary with the following structure:

    .. code-block:: python

        {
            'user': {
                'email': '...',
                'profile': {
                    'username': '...',
                    'full_name': '...',
                }
            },
            'external_id': 'owncloud-unique-identifier',
            'external_method': 'owncloud',
        }

    Information inside the user dictionary are available for other modules.
    For example, they are used from the module invenio-userprofiles to fill
    the user profile.

    :param remote: The remote application.
    :param resp: The response.
    :returns: A dictionary with the user information.
    """
    info = get_user_info(remote)

    return {
        'user': {
            'email': info['email'],
            'profile': {
                'username': info['username'],
                'full_name': '%s %s' % (info['name'], info['family_name'])
            },
        },
        'external_id': get_user_id(remote, info['email']),
        'external_method': _owncloud_app.external_method
    }


@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Handle unlinking of remote account."""
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )
    external_id = account.extra_data.get("id")

    if external_id:
        oauth_unlink_external_id(dict(id=external_id, method="owncloud"))
    if account:
        with db.session.begin_nested():
            account.delete()

    token_delete(remote)


def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of remote account."""
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))


def get_user_id(remote, email):
    """Get the Owncloud identity for a users given email."""
    try:
        url = '{}?usernames={}'.format(_owncloud_app.user_info_url, email)
        user_id = get_dict_from_response(remote.get(url))
        return user_id['sub']
    except KeyError:
        # If we got here the response was successful but the data was invalid.
        # It's likely the URL is wrong but possible the API has changed.
        raise OAuthResponseError('Failed to fetch user id, likely server '
                                 'mis-configuration', None, remote)


def account_setup(remote, token, resp):
    """Perform additional setup after user have been logged in."""

    info = get_user_info(remote)
    user_id = get_user_id(remote, info['email'])

    with db.session.begin_nested():
        token.remote_account.extra_data = {
            'login': info['username'],
            'id': user_id}
        oauth_link_external_id(
                token.remote_account.user, dict(
                    id=user_id,
                    method=_owncloud_app.external_method)
            )
