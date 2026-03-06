# coding: utf-8

"""
POP3 (Post Office Protocol v3) parser for extracting credentials.

Supports:
- USER / PASS commands  (RFC 1939, most common POP3 auth)
- AUTH PLAIN            (RFC 4616 SASL PLAIN, one-step base64 blob)
- AUTH LOGIN            (two-step base64 challenge/response)

Auth state machine stored in the session dict:
  session["pop_state"] :
      None         — idle
      "USER_SENT"  — USER command seen, waiting for PASS
      "PASS_SENT"  — PASS received, waiting for +OK/-ERR
      "AUTH_PLAIN" — AUTH PLAIN started, waiting for SASL blob
      "AUTH_LOGIN" — AUTH LOGIN started
      "AUTH_DONE"  — credentials assembled, waiting for +OK/-ERR
  session["pop_auth_step"] : 0 | 1 (for AUTH LOGIN)
"""

import base64

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import utils, logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    current_creds = session.credentials_being_built

    if hasattr(layer, "request_command"):
        command = layer.request_command

        # ------------------------------------------------------------------
        # USER / PASS — plaintext credential commands (RFC 1939 §7)
        # ------------------------------------------------------------------
        if command == "USER" and hasattr(layer, "request_parameter"):
            current_creds.username = layer.request_parameter
            session["pop_state"] = "USER_SENT"
            logger.info(session, f"POP3 USER: {current_creds.username}")

        elif command == "PASS" and session["pop_state"] == "USER_SENT":
            if hasattr(layer, "request_parameter"):
                current_creds.password = layer.request_parameter
                session["pop_state"] = "PASS_SENT"
                logger.info(session, "POP3 PASS received")

        # ------------------------------------------------------------------
        # AUTH — SASL mechanisms
        # ------------------------------------------------------------------
        elif command == "AUTH" and hasattr(layer, "request_parameter"):
            parameter = layer.request_parameter
            if parameter == "PLAIN":
                session["pop_state"] = "AUTH_PLAIN"
                logger.info(session, "POP3 AUTH PLAIN started")
            elif parameter == "LOGIN":
                session["pop_state"] = "AUTH_LOGIN"
                session["pop_auth_step"] = 0
                logger.info(session, "POP3 AUTH LOGIN started")

        # ------------------------------------------------------------------
        # SASL continuation data
        # ------------------------------------------------------------------
        elif session["pop_state"] == "AUTH_PLAIN":
            try:
                current_creds.username, current_creds.password = utils.parse_sasl_creds(
                    command, "PLAIN"
                )
                session["pop_state"] = "AUTH_DONE"
                logger.info(session, f"POP3 PLAIN auth user: {current_creds.username}")
            except Exception as e:
                logger.info(session, f"POP3 PLAIN decode error: {e}")

        elif session["pop_state"] == "AUTH_LOGIN":
            step = session["pop_auth_step"] or 0
            try:
                decoded = base64.b64decode(command).decode("utf-8", errors="ignore")
                if step == 0:
                    current_creds.username = decoded
                    session["pop_auth_step"] = 1
                    logger.info(session, f"POP3 AUTH LOGIN username: {decoded}")
                else:
                    current_creds.password = decoded
                    session["pop_auth_step"] = 0
                    session["pop_state"] = "AUTH_DONE"
                    logger.info(session, "POP3 AUTH LOGIN password received")
            except Exception as e:
                logger.info(session, f"POP3 AUTH LOGIN decode error: {e}")

    # ----------------------------------------------------------------------
    # Server response
    # ----------------------------------------------------------------------
    if hasattr(layer, "response_indicator"):
        indicator = layer.response_indicator
        state = session["pop_state"]

        if indicator == "+OK":
            # Only validate when we have assembled a full credential set.
            # A +OK after USER simply acknowledges the username — we must
            # wait for the +OK that follows PASS / the SASL exchange.
            if state in ("PASS_SENT", "AUTH_DONE") and current_creds.username:
                logger.found(
                    session,
                    "credentials found: {} -- {}".format(
                        current_creds.username, current_creds.password
                    ),
                )
                session.validate_credentials()
                session["pop_state"] = None

        elif indicator == "-ERR":
            if current_creds.username or state:
                logger.info(
                    session, f"POP3 auth failed for user: {current_creds.username}"
                )
                session.invalidate_credentials_and_clear_session()
