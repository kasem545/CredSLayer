# coding: utf-8

"""
SIP (Session Initiation Protocol) parser for extracting VoIP credentials.
SIP is used for voice and video calls over IP networks.
"""

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    """
    Analyze SIP protocol packets for authentication credentials.

    SIP authentication uses Digest authentication with Authorization header.
    We extract username, realm, and digest response.
    """

    current_creds = session.credentials_being_built

    # Check for SIP Authorization header
    if hasattr(layer, "authorization"):
        auth_header = layer.authorization
        logger.info(session, f"SIP Authorization header found: {auth_header}")

        # Extract username from Authorization header
        # Format: Digest username="user", realm="example.com", ...
        if 'username=' in auth_header:
            try:
                username_start = auth_header.find('username="') + len('username="')
                username_end = auth_header.find('"', username_start)
                username = auth_header[username_start:username_end]
                current_creds.username = username
            except Exception as e:
                logger.info(session, f"Failed to extract SIP username: {e}")

        # Extract realm
        if 'realm=' in auth_header:
            try:
                realm_start = auth_header.find('realm="') + len('realm="')
                realm_end = auth_header.find('"', realm_start)
                realm = auth_header[realm_start:realm_end]
                current_creds.context["Realm"] = realm
            except Exception as e:
                logger.info(session, f"Failed to extract SIP realm: {e}")

        # Extract response (digest hash)
        if 'response=' in auth_header:
            try:
                response_start = auth_header.find('response="') + len('response="')
                response_end = auth_header.find('"', response_start)
                response = auth_header[response_start:response_end]
                current_creds.hash = response
            except Exception as e:
                logger.info(session, f"Failed to extract SIP response: {e}")

    # Check for WWW-Authenticate header in response
    if hasattr(layer, "www_authenticate"):
        logger.info(session, f"SIP WWW-Authenticate header found: {layer.www_authenticate}")

    # Check for From and To headers to gather context
    if hasattr(layer, "from_user"):
        logger.info(session, f"SIP From user: {layer.from_user}")
        if not current_creds.username:
            current_creds.username = layer.from_user

    if hasattr(layer, "to_user"):
        logger.info(session, f"SIP To user: {layer.to_user}")
        current_creds.context["To"] = layer.to_user

    # If we found credentials, log them
    if current_creds.username or current_creds.hash:
        current_creds.context["Protocol"] = "SIP/VoIP"
        logger.found(session, f"SIP credentials found: {current_creds.username} -- {current_creds.hash}")
        session.credentials_list.append(current_creds)
