# coding: utf-8

"""
FTP (File Transfer Protocol) parser for extracting credentials.
Supports both active and passive FTP modes.
"""

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    """
    Analyze FTP protocol packets for authentication credentials.

    FTP sends credentials in clear text with USER and PASS commands.
    Response code 230 indicates successful login.
    Response code 430/530 indicates failed login.
    """

    current_creds = session.credentials_being_built

    try:
        if hasattr(layer, "response_code"):
            code = int(layer.response_code)

            if code == 230 and current_creds.username:
                logger.found(session, f"FTP credentials found: {current_creds.username} -- {current_creds.password}")
                session.validate_credentials()

            elif code in [430, 530]:  # Failed login
                logger.info(session, f"FTP login failed for user: {current_creds.username}")
                session.invalidate_credentials_and_clear_session()

        elif hasattr(layer, "request_command"):
            command = layer.request_command

            if command == "USER" and hasattr(layer, "request_arg"):
                current_creds.username = layer.request_arg
                logger.info(session, f"FTP username: {current_creds.username}")

            elif command == "PASS" and hasattr(layer, "request_arg"):
                current_creds.password = layer.request_arg
                logger.info(session, f"FTP password received")

    except (ValueError, AttributeError) as e:
        logger.info(session, f"Error parsing FTP packet: {e}")
