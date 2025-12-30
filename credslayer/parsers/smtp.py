# coding: utf-8

"""
SMTP (Simple Mail Transfer Protocol) parser for extracting credentials.
Supports PLAIN and LOGIN authentication mechanisms.
"""

from base64 import b64decode

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import utils, logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    """
    Analyze SMTP protocol packets for authentication credentials.

    Supports:
    - AUTH PLAIN (SASL)
    - AUTH LOGIN
    - Response codes: 235 (success), 535 (failure)
    """

    current_creds = session.credentials_being_built

    try:
        if hasattr(layer, "req_command"):
            command = layer.req_command

            if hasattr(layer, "req_parameter"):
                parameter = layer.req_parameter

                if command == "AUTH":
                    if parameter.startswith("LOGIN"):
                        session["auth_process_login"] = True
                        logger.info(session, "SMTP LOGIN authentication started")
                    elif parameter.startswith("PLAIN"):
                        session["auth_process_plain"] = True
                        logger.info(session, "SMTP PLAIN authentication started")

        if session["auth_process_login"]:
            if hasattr(layer, "auth_username"):
                username = layer.auth_username
                current_creds.username = b64decode(username).decode('utf-8', errors='ignore')
                logger.info(session, f"SMTP username: {current_creds.username}")

            elif hasattr(layer, "auth_password"):
                password = layer.auth_password
                current_creds.password = b64decode(password).decode('utf-8', errors='ignore')
                logger.info(session, "SMTP password received")
                session["auth_process_login"] = False

        elif session["auth_process_plain"]:
            if hasattr(layer, "auth_username"):
                b64_auth = layer.auth_username
                current_creds.username, current_creds.password = utils.parse_sasl_creds(b64_auth, "PLAIN")
                logger.info(session, f"SMTP PLAIN auth: {current_creds.username}")
                session["auth_process_plain"] = False

        if hasattr(layer, "response_code"):
            response_code = int(layer.response_code)

            if response_code == 235 and current_creds.username:
                logger.found(session, f"SMTP credentials found: {current_creds.username} -- {current_creds.password}")
                session.validate_credentials()

            elif response_code == 535:  # Auth failed
                logger.info(session, f"SMTP auth failed for user: {current_creds.username}")
                session.invalidate_credentials_and_clear_session()

    except (ValueError, AttributeError, TypeError, UnicodeDecodeError) as e:
        logger.info(session, f"Error parsing SMTP packet: {e}")
