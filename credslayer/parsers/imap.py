# coding: utf-8

"""
IMAP (Internet Message Access Protocol) parser for extracting credentials.

Supports:
- Plaintext LOGIN command
- AUTHENTICATE PLAIN  (RFC 4616 SASL PLAIN)
- AUTHENTICATE LOGIN  (two-step base64 challenge/response)

Auth state machine stored in the session dict:
  session["imap_auth"]       : None | "PLAIN" | "LOGIN"
  session["imap_auth_step"]  : 0 (waiting username) | 1 (waiting password)
  session["imap_auth_on"]    : True while any AUTHENTICATE sequence is active
"""

import base64

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger, utils
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    current_creds = session.credentials_being_built

    if hasattr(layer, "request_command"):
        command = layer.request_command

        # ------------------------------------------------------------------
        # Plaintext LOGIN command: LOGIN "username" "password"
        # ------------------------------------------------------------------
        if command == "LOGIN":
            tokens = layer.request.split('"')
            current_creds.username = tokens[1]
            current_creds.password = tokens[3]
            session["imap_auth_on"] = True

        # ------------------------------------------------------------------
        # SASL AUTHENTICATE command
        # ------------------------------------------------------------------
        elif command == "AUTHENTICATE":
            if hasattr(layer, "request_parameter"):
                mechanism = layer.request_parameter.upper()
                if mechanism == "PLAIN":
                    session["imap_auth"] = "PLAIN"
                    session["imap_auth_on"] = True
                    logger.info(session, "IMAP AUTHENTICATE PLAIN started")
                elif mechanism == "LOGIN":
                    session["imap_auth"] = "LOGIN"
                    session["imap_auth_step"] = 0
                    session["imap_auth_on"] = True
                    logger.info(session, "IMAP AUTHENTICATE LOGIN started")

        # ------------------------------------------------------------------
        # Continuation data (SASL payload sent without a tagged command)
        # ------------------------------------------------------------------
        elif session["imap_auth"] == "PLAIN":
            # Entire SASL PLAIN blob: base64("\0authzid\0authcid\0passwd")
            try:
                current_creds.username, current_creds.password = utils.parse_sasl_creds(
                    command, "PLAIN"
                )
                logger.info(session, f"IMAP PLAIN auth user: {current_creds.username}")
            except Exception as e:
                logger.info(session, f"IMAP PLAIN decode error: {e}")
            finally:
                session["imap_auth"] = None  # blob consumed

        elif session["imap_auth"] == "LOGIN":
            step = session["imap_auth_step"] or 0
            try:
                decoded = base64.b64decode(command).decode("utf-8", errors="ignore")
                if step == 0:
                    current_creds.username = decoded
                    session["imap_auth_step"] = 1
                    logger.info(session, f"IMAP LOGIN auth username: {decoded}")
                else:
                    current_creds.password = decoded
                    session["imap_auth"] = None
                    session["imap_auth_step"] = 0
                    logger.info(session, "IMAP LOGIN auth password received")
            except Exception as e:
                logger.info(session, f"IMAP LOGIN decode error: {e}")

    # ----------------------------------------------------------------------
    # Server response — validate or discard pending credentials
    # ----------------------------------------------------------------------
    # Due to an incompatibility with "old" tshark versions, we cannot use
    # response_command, so we parse the full response string instead.
    elif hasattr(layer, "response"):
        response = layer.response
        status = layer.response_status

        auth_in_progress = (
            session["imap_auth_on"]
            or " LOGIN " in response
            or " AUTHENTICATE " in response
        )

        if auth_in_progress:
            if status == "OK" and current_creds.username:
                logger.found(
                    session,
                    "credentials found: {} -- {}".format(
                        current_creds.username, current_creds.password
                    ),
                )
                session.validate_credentials()
                session["imap_auth_on"] = False

            elif status in ("NO", "BAD"):
                logger.info(session, "IMAP auth failed")
                session.invalidate_credentials_and_clear_session()
