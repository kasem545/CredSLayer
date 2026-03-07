# coding: utf-8

"""
IMAP (Internet Message Access Protocol) parser for extracting credentials.

Supports:
- Plaintext LOGIN command
- AUTHENTICATE PLAIN  (RFC 4616 SASL PLAIN)
- AUTHENTICATE LOGIN  (two-step base64 challenge/response)

tshark field → layer attribute mapping (pyshark XML mode):
  imap.request_command  → layer.request_command  (e.g. "AUTHENTICATE", "LOGIN")
  imap.request          → layer.request          (full request line, e.g. "a002 AUTHENTICATE PLAIN")
  imap.response         → layer.response         (full response line)
  imap.response_status  → layer.response_status  (e.g. "OK", "NO", "BAD")
  imap.response_command → layer.response_command (present on tagged OK/NO responses)

SASL continuation packets have NO request_command — tshark exposes the base64
blob via layer.request (and layer.request_tag).

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
        # SASL AUTHENTICATE command — mechanism is in the full request line
        # e.g. "a002 AUTHENTICATE PLAIN" → split()[2] = "PLAIN"
        # ------------------------------------------------------------------
        elif command == "AUTHENTICATE":
            parts = layer.request.split()
            mechanism = parts[2].upper() if len(parts) >= 3 else ""
            if mechanism == "PLAIN":
                session["imap_auth"] = "PLAIN"
                session["imap_auth_on"] = True
                logger.info(session, "IMAP AUTHENTICATE PLAIN started")
            elif mechanism == "LOGIN":
                session["imap_auth"] = "LOGIN"
                session["imap_auth_step"] = 0
                session["imap_auth_on"] = True
                logger.info(session, "IMAP AUTHENTICATE LOGIN started")

    # -----------------------------------------------------------------------
    # SASL continuation blobs: no request_command, base64 data in layer.request
    # -----------------------------------------------------------------------
    elif hasattr(layer, "request") and not hasattr(layer, "request_command"):
        blob = layer.request.strip()

        if session["imap_auth"] == "PLAIN":
            try:
                current_creds.username, current_creds.password = utils.parse_sasl_creds(
                    blob, "PLAIN"
                )
                logger.info(session, f"IMAP PLAIN auth user: {current_creds.username}")
            except Exception as e:
                logger.info(session, f"IMAP PLAIN decode error: {e}")
            finally:
                session["imap_auth"] = None  # blob consumed

        elif session["imap_auth"] == "LOGIN":
            step = session["imap_auth_step"] or 0
            try:
                decoded = base64.b64decode(blob).decode("utf-8", errors="ignore")
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
    elif hasattr(layer, "response"):
        response = layer.response
        status = getattr(layer, "response_status", "")

        auth_in_progress = (
            session["imap_auth_on"]
            or " LOGIN " in response
            or " AUTHENTICATE " in response
            or getattr(layer, "response_command", "") == "AUTHENTICATE"
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
