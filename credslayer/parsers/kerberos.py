# coding: utf-8

"""
Kerberos (RFC 4120) parser for extracting authentication artefacts.

Captures three classes of interesting material:

1. AS-REQ (msg_type=10)
   Reveals the requesting principal name and realm — useful for user
   enumeration even when pre-authentication is required.

2. AS-REP Roasting (msg_type=11)
   When an account has "Do not require Kerberos pre-authentication" set,
   the KDC returns an AS-REP whose enc-part is encrypted with the user's
   password-derived key.  This encrypted blob can be cracked offline.
   Hash format (Hashcat mode 18200):
       $krb5asrep$<etype>$<username>@<REALM>:<cipher-hex>

3. Kerberoasting (msg_type=13, TGS-REP)
   Service tickets in TGS-REP are encrypted with the service account's
   NTLM hash.  Any authenticated user can request them, and the ticket
   can be cracked offline to recover the service account's password.
   Hash format (Hashcat mode 13100):
       $krb5tgs$<etype>$*<username>$<REALM>$<service>*$<cipher-hex>

tshark field → layer attribute mapping (pyshark dot→underscore):
  kerberos.msg_type           → layer.msg_type
  kerberos.realm              → layer.realm
  kerberos.cname.name_string  → layer.cname_name_string
  kerberos.sname.name_string  → layer.sname_name_string
  kerberos.etype              → layer.etype
  kerberos.cipher             → layer.cipher  (colon-separated hex bytes)

Session state:
  session["krb_username"] : client principal from AS-REQ / AS-REP
  session["krb_realm"]    : realm from AS-REQ / AS-REP
  session["krb_sname"]    : service name from TGS-REQ
"""

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session
from credslayer.core.utils import Credentials

# Kerberos message type constants (RFC 4120 §7.5.7)
_AS_REQ = "10"
_AS_REP = "11"
_TGS_REQ = "12"
_TGS_REP = "13"


def analyse(session: Session, layer: BaseLayer) -> bool:
    msg_type = getattr(layer, "msg_type", None)

    if msg_type is None:
        return False

    logger.debug(f"Kerberos msg_type={msg_type}")

    if msg_type == _AS_REQ:
        _handle_as_req(session, layer)

    elif msg_type == _AS_REP:
        _handle_as_rep(session, layer)

    elif msg_type == _TGS_REQ:
        _handle_tgs_req(session, layer)

    elif msg_type == _TGS_REP:
        _handle_tgs_rep(session, layer)

    return True


# ---------------------------------------------------------------------------
# Internal handlers
# ---------------------------------------------------------------------------


def _handle_as_req(session: Session, layer: BaseLayer):
    """
    AS-REQ — record requesting principal for later use and user enumeration.
    """
    username = getattr(layer, "cname_name_string", None)
    realm = getattr(layer, "realm", None)

    if username:
        session["krb_username"] = username
        session["krb_realm"] = realm
        logger.info(session, f"Kerberos AS-REQ: {username}@{realm}")


def _handle_as_rep(session: Session, layer: BaseLayer):
    """
    AS-REP — extract encrypted blob for AS-REP Roasting.

    The enc-part cipher is encrypted with the user's password-derived key.
    Capture it so the analyst can attempt offline cracking with hashcat
    (mode 18200).
    """
    username = session["krb_username"] or getattr(layer, "cname_name_string", None)
    realm = session["krb_realm"] or getattr(layer, "realm", None)
    etype = getattr(layer, "etype", "23")  # default to RC4 if unknown
    cipher = getattr(layer, "cipher", None)

    if not (username and cipher):
        return

    cipher_hex = cipher.replace(":", "")
    hash_value = "$krb5asrep${}${}@{}:{}".format(etype, username, realm, cipher_hex)

    creds = Credentials()
    creds.username = username
    creds.hash = hash_value
    creds.context["Realm"] = realm
    creds.context["EType"] = etype
    creds.context["Type"] = "AS-REP Roasting"

    logger.found(
        session,
        f"Kerberos AS-REP Roasting hash captured for {username}@{realm} "
        f"(hashcat -m 18200)",
    )
    session.credentials_list.append(creds)


def _handle_tgs_req(session: Session, layer: BaseLayer):
    """
    TGS-REQ — record the requested service name so TGS-REP can reference it.
    """
    sname = getattr(layer, "sname_name_string", None)
    if sname:
        session["krb_sname"] = sname
        logger.info(session, f"Kerberos TGS-REQ for service: {sname}")


def _handle_tgs_rep(session: Session, layer: BaseLayer):
    """
    TGS-REP — extract service ticket for Kerberoasting.

    The ticket's enc-part is encrypted with the service account's NTLM hash.
    Any authenticated domain user can request these tickets.  Capture the
    cipher so the analyst can attempt offline cracking with hashcat
    (mode 13100).
    """
    username = session["krb_username"] or getattr(layer, "cname_name_string", None)
    realm = getattr(layer, "realm", None) or session["krb_realm"]
    sname = session["krb_sname"] or getattr(layer, "sname_name_string", None)
    etype = getattr(layer, "etype", "23")
    cipher = getattr(layer, "cipher", None)

    if not cipher:
        return

    cipher_hex = cipher.replace(":", "")
    svc_label = sname or "unknown"

    hash_value = "$krb5tgs${}$*{}${}${}*${}".format(
        etype, username or "unknown", realm or "unknown", svc_label, cipher_hex
    )

    creds = Credentials()
    creds.username = username
    creds.hash = hash_value
    creds.context["Realm"] = realm
    creds.context["Service"] = svc_label
    creds.context["EType"] = etype
    creds.context["Type"] = "Kerberoasting"

    logger.found(
        session,
        f"Kerberoasting hash captured for service '{svc_label}' "
        f"(requested by {username}@{realm}) (hashcat -m 13100)",
    )
    session.credentials_list.append(creds)
