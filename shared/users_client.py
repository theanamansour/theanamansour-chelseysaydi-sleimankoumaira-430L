"""
Reads user information from Service 1 (Users and Identity Management, Theana Mansour).

Each service has its own database, so a user ID stored in our tables (an asset's owner,
a notification's recipient) is checked by asking Service 1 instead of a SQLite foreign key.
"""
import requests

from shared import config


class UsersServiceUnavailable(Exception):
    """Service 1 could not be reached or refused the request."""


def list_users(authorization_header):
    """
    Return the list of users from GET /theana-mansour/users.
    Only Security Administrators and Auditors may call it, so the caller's own token is forwarded.
    """
    try:
        response = requests.get(
            config.USERS_LIST_URL,
            headers={"Authorization": authorization_header},
            timeout=config.REQUEST_TIMEOUT,
        )
        users = response.json()
    except (requests.RequestException, ValueError) as problem:
        raise UsersServiceUnavailable() from problem

    if response.status_code != 200 or not isinstance(users, list):
        raise UsersServiceUnavailable()
    return users


def user_exists(user_id, authorization_header):
    """True if Service 1 has a user with this ID."""
    return any(user.get("id") == user_id for user in list_users(authorization_header))
