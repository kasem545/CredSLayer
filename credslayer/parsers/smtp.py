# coding: utf-8

"""
SMTP (Simple Mail Transfer Protocol) parser for extracting credentials.

Supports:
- AUTH PLAIN   (RFC 4616 SASL PLAIN, one-step base64 blob)
- AUTH LOGIN   (two-step base64 challenge/response)
- AUTH CRAM-MD5 (RFC 2195, challenge/response — hash stored for offline cracking)

Response codes:
  235 — authentication succeeded
  334 — server continuation (challenge)
  535 — authentication failed

Auth state machine stored in the session dict:
  session["auth_process_login"]    : True while AUTH LOGIN is active
  session["auth_process_plain"]    : True while AUTH PLAIN is active
  session["auth_process_cram_md5"] : True while AUTH CRAM-MD5 is active
  session["cram_md5_challenge"]    : base64 string of the CRAM-MD5 challenge
"""

from base64 import b64decode

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import utils, logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    """
    Analyse SMTP protocol packets for authentication credentials.

    Supports:
    - AUTH PLAIN (SASL)
    - AUTH LOGIN
    - AUTH CRAM-MD5
    - Response codes: 235 (success), 334 (challenge), 535 (failure)
    """

    current_creds = session.credentials_being_built

    try:
        # ------------------------------------------------------------------
        # Client → Server: commands
        # ------------------------------------------------------------------
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
                    elif parameter.startswith("CRAM-MD5"):
                        session["auth_process_cram_md5"] = True
                        logger.info(session, "SMTP CRAM-MD5 authentication started")

            # --- AUTH CRAM-MD5 client reply (base64 blob, no req_parameter) ---
            # The client sends: base64("username HMAC-MD5-hex")
            # tshark surfaces this as req_command when no named field exists.
            elif session["auth_process_cram_md5"]:
                try:
                    decoded = b64decode(command).decode("utf-8", errors="ignore")
                    parts = decoded.split(" ", 1)
                    if len(parts) == 2:
                        current_creds.username = parts[0]
                        challenge_b64 = session["cram_md5_challenge"] or ""
                        current_creds.hash = "{}:{}".format(challenge_b64, parts[1])
                        current_creds.context["Mechanism"] = "CRAM-MD5"
                        session["auth_process_cram_md5"] = False
                        logger.info(session,
                                    f"SMTP CRAM-MD5 response for {current_creds.username}")
                except Exception as e:
                    logger.info(session, f"SMTP CRAM-MD5 decode error: {e}")

        # ------------------------------------------------------------------
        # AUTH LOGIN / PLAIN continuations — these live *outside* the
        # req_command guard because tshark may surface auth_username and
        # auth_password on packets that lack a req_command field.
        # ------------------------------------------------------------------
        if session["auth_process_login"]:
            if hasattr(layer, "auth_username"):
                username = layer.auth_username
                current_creds.username = b64decode(username).decode(
                    "utf-8", errors="ignore")
                logger.info(session, f"SMTP username: {current_creds.username}")

            elif hasattr(layer, "auth_password"):
                password = layer.auth_password
                current_creds.password = b64decode(password).decode(
                    "utf-8", errors="ignore")
                logger.info(session, "SMTP password received")
                session["auth_process_login"] = False

        elif session["auth_process_plain"]:
            if hasattr(layer, "auth_username"):
                b64_auth = layer.auth_username
                current_creds.username, current_creds.password = \
                    utils.parse_sasl_creds(b64_auth, "PLAIN")
                logger.info(session, f"SMTP PLAIN auth: {current_creds.username}")
                session["auth_process_plain"] = False

        # ------------------------------------------------------------------
        # Server → Client: response codes
        # ------------------------------------------------------------------
        if hasattr(layer, "response_code"):
            response_code = int(layer.response_code)

            if response_code == 334:
                # Continuation challenge — capture for CRAM-MD5 context
                if session["auth_process_cram_md5"]:
                    challenge_b64 = getattr(layer, "response_parameter", "")
                    session["cram_md5_challenge"] = challenge_b64
                    logger.info(session, "SMTP CRAM-MD5 challenge received")

            elif response_code == 235 and current_creds.username:
                logger.found(
                    session,
                    f"SMTP credentials found: "
                    f"{current_creds.username} -- "
                    f"{current_creds.password or current_creds.hash}",
                )
                session.validate_credentials()

            elif response_code == 535:
                logger.info(
                    session, f"SMTP auth failed for user: {current_creds.username}"
                )
                session.invalidate_credentials_and_clear_session()

    except (ValueError, AttributeError, TypeError, UnicodeDecodeError) as e:
        logger.info(session, f"Error parsing SMTP packet: {e}")
