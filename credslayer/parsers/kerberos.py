# coding: utf-8

"""
Kerberos (RFC 4120) parser — cipher extraction modelled after roasting.py
(MIT License, Javier Álvarez, 2024).

Three hash classes are captured:

1. AS-REQ Pre-auth (msg_type=10, PA-ENC-TIMESTAMP)
   When a KDC enforces pre-authentication the client encrypts a timestamp with
   its password-derived key.  The cipher can be cracked offline.
   Hash format (Hashcat mode 19900):
       $krb5pa$<etype>$<username>$<REALM>$<cipher-hex>

2. AS-REP Roasting (msg_type=11)
   When an account has "Do not require Kerberos pre-authentication" the KDC
   returns an AS-REP whose enc-part is encrypted with the user's password.
   Two kerberos.cipher values appear in each AS-REP packet (in stream order):
       [0] Ticket.enc-part   — encrypted with the KDC's key (not crackable)
       [1] KDC-REP.enc-part  — encrypted with the user's password  ← roasting target
   Hash format (Hashcat mode 18200):
       $krb5asrep$<etype>$<username>@<REALM>:<checksum>$<enc-data>
   where <checksum> = first 16 bytes (32 hex chars) of the KDC-REP.enc-part cipher.

3. Kerberoasting (msg_type=13, TGS-REP)
   Service tickets are encrypted with the service account's NTLM hash.
   Two kerberos.cipher values appear in each TGS-REP packet (in stream order):
       [0] Ticket.enc-part   — encrypted with the service account's NTLM hash ← target
       [1] KDC-REP.enc-part  — encrypted with the TGT session key (not crackable)
   Hash format (Hashcat mode 13100):
       $krb5tgs$<etype>$*<username>$<REALM>$<service>*$<checksum>$<enc-data>
   where <checksum> = first 16 bytes (32 hex chars) of the ticket cipher.

pyshark field → layer attribute mapping (XML/JSON mode, kerberos. prefix stripped):
  kerberos.msg_type    → layer.msg_type
  kerberos.realm       → layer.realm      (AS-REQ realm)
  kerberos.crealm      → layer.crealm     (AS-REP / TGS-REP client realm)
  kerberos.CNameString → layer.CNameString (requesting principal)
  kerberos.SNameString → layer.SNameString (service name, TGS-REQ/REP)
  kerberos.etype       → layer.etype
  kerberos.cipher      → layer.cipher  (hex, colon-separated per byte)

Multiple kerberos.cipher / kerberos.etype values are accessed via
layer.get_field('cipher').all_fields, preserving stream order so that
index [0] is always the Ticket cipher and index [-1] is the KDC-REP enc-part.

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
_AP_REQ = "14"
_KRB_ERROR = "30"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_all_ciphers(layer: BaseLayer):
    """
    Return every kerberos.cipher value from *layer* as a list of plain hex
    strings (no colon separators), in the order tshark emits them (stream
    order).  Returns [] when no cipher field is present.
    """
    cf = layer.get_field("cipher")
    if cf is None:
        return []
    try:
        fields = cf.all_fields
    except AttributeError:
        fields = [cf]
    return [f.raw_value for f in fields if f is not None and f.raw_value]


def _get_all_msg_types(layer: BaseLayer):
    """
    Return every kerberos.msg_type value from *layer* as a list of strings,
    in the order tshark emits them.  Returns [] when no msg_type field is
    present.  Compound packets (e.g. FAST AS-REQ+AP-REQ) return multiple
    values such as ["10", "14"].
    """
    f = layer.get_field("msg_type")
    if f is None:
        return []
    try:
        return [x.show for x in f.all_fields]
    except AttributeError:
        val = getattr(layer, "msg_type", None)
        return [val] if val else []


def _split_cipher(cipher_hex: str):
    """
    Split a cipher hex string into (checksum, enc_data) at the 16-byte
    (32 hex char) boundary, matching Hashcat's expected input format.
    """
    return cipher_hex[:32], cipher_hex[32:]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyse(session: Session, layer: BaseLayer) -> bool:
    msg_types = _get_all_msg_types(layer)

    if not msg_types:
        return False

    is_compound = len(msg_types) > 1

    for msg_type in msg_types:
        logger.debug(f"Kerberos msg_type={msg_type}")

        if msg_type == _AS_REQ:
            _handle_as_req(session, layer, is_compound=is_compound)

        elif msg_type == _AS_REP:
            _handle_as_rep(session, layer)

        elif msg_type == _TGS_REQ:
            _handle_tgs_req(session, layer)

        elif msg_type == _TGS_REP:
            _handle_tgs_rep(session, layer)

        # _AP_REQ (14) and _KRB_ERROR (30) → intentionally no-op

    return True

# ---------------------------------------------------------------------------
# Internal handlers
# ---------------------------------------------------------------------------


def _handle_as_req(session: Session, layer: BaseLayer, is_compound: bool = False):
    """
    AS-REQ — record requesting principal and extract PA-ENC-TIMESTAMP cipher.

    When padata is present (pre-auth enforced), kerberos.cipher carries the
    PA-ENC-TIMESTAMP blob encrypted with the user's password.  This yields a
    $krb5pa$ hash crackable offline (Hashcat mode 19900).
    """
    username = getattr(layer, "CNameString", None)
    realm = getattr(layer, "realm", None)

    if username:
        session["krb_username"] = username
        session["krb_realm"] = realm
        logger.info(session, f"Kerberos AS-REQ: {username}@{realm}")

    # PA-ENC-TIMESTAMP cipher is the only cipher in a standalone AS-REQ.
    # In FAST-protected (compound) packets the layer contains ciphers from
    # the embedded AP-REQ armor as well; ciphers[0] would be the AP-REQ
    # armor TGT cipher — NOT the user's PA-ENC-TIMESTAMP — which would
    # produce a crackable-looking but completely wrong hash.  Skip.
    if is_compound:
        return

    ciphers = _get_all_ciphers(layer)
    if not (username and ciphers):
        return

    etype = getattr(layer, "etype", "18")
    cipher_hex = ciphers[0]

    hash_value = f"$krb5pa${etype}${username}${realm}${cipher_hex}"

    creds = Credentials()
    creds.username = username
    creds.hash = hash_value
    creds.context["Realm"] = realm
    creds.context["EType"] = etype
    creds.context["Type"] = "AS-REQ Pre-auth"

    logger.found(
        session,
        f"Kerberos AS-REQ Pre-auth hash captured for {username}@{realm} "
        f"(hashcat -m 19900)",
    )
    session.credentials_list.append(creds)


def _handle_as_rep(session: Session, layer: BaseLayer):
    """
    AS-REP — extract KDC-REP.enc-part cipher for AS-REP Roasting.

    Stream order of kerberos.cipher in an AS-REP packet:
        [0]  Ticket.enc-part  (encrypted with KDC key — not useful)
        [-1] KDC-REP.enc-part (encrypted with user's password — roasting target)

    Hash format: $krb5asrep$<etype>$<user>@<REALM>:<checksum>$<enc_data>
    (Hashcat mode 18200)
    """
    username = session["krb_username"] or getattr(layer, "CNameString", None)
    realm = session["krb_realm"] or getattr(layer, "crealm", None)
    etype = getattr(layer, "etype", "23")

    ciphers = _get_all_ciphers(layer)
    if not (username and ciphers):
        return

    # Last cipher = KDC-REP.enc-part = encrypted with user's password key
    cipher_hex = ciphers[-1]
    checksum, enc_data = _split_cipher(cipher_hex)

    hash_value = f"$krb5asrep${etype}${username}@{realm}:{checksum}${enc_data}"

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
    sname = getattr(layer, "SNameString", None) or getattr(layer, "snamestring", None)
    if sname:
        session["krb_sname"] = sname
        logger.info(session, f"Kerberos TGS-REQ for service: {sname}")


def _handle_tgs_rep(session: Session, layer: BaseLayer):
    """
    TGS-REP — extract Ticket.enc-part cipher for Kerberoasting.

    Stream order of kerberos.cipher in a TGS-REP packet:
        [0]  Ticket.enc-part  (encrypted with service account NTLM — target)
        [1]  KDC-REP.enc-part (encrypted with TGT session key — not useful)

    SPN parts from kerberos.SNameString may be comma-separated; join with '/'.

    Hash format: $krb5tgs$<etype>$*<user>$<REALM>$<service>*$<checksum>$<enc_data>
    (Hashcat mode 13100)
    """
    username = session["krb_username"] or getattr(layer, "CNameString", None)
    realm = getattr(layer, "crealm", None) or session["krb_realm"]
    sname = session["krb_sname"] or getattr(layer, "SNameString", None)
    etype = getattr(layer, "etype", "23")

    ciphers = _get_all_ciphers(layer)
    if not ciphers:
        return

    # First cipher = Ticket.enc-part = encrypted with service account's NTLM hash
    cipher_hex = ciphers[0]
    checksum, enc_data = _split_cipher(cipher_hex)

    # Normalise SPN: tshark emits multi-component names comma-separated
    svc_label = (sname or "unknown").replace(",", "/")

    hash_value = (
        f"$krb5tgs${etype}$*{username or 'unknown'}"
        f"${realm or 'unknown'}${svc_label}*"
        f"${checksum}${enc_data}"
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
