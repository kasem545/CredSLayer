# coding: utf-8
import re

from pyshark.packet.layers.base import BaseLayer
from credslayer.core import logger
from credslayer.core.session import Session

_SCRAM_MECHANISMS = frozenset({"SCRAM-SHA-1", "SCRAM-SHA-256"})

# RFC 5802 §5.1 attribute regexes
_RE_N = re.compile(r"(?:^|,)n=([^,]+)")  # username (client-first-bare)
_RE_R = re.compile(r"(?:^|,)r=([^,]+)")  # nonce
_RE_S = re.compile(r"(?:^|,)s=([^,]+)")  # salt (base64)
_RE_I = re.compile(r"(?:^|,)i=(\d+)")  # iteration count
_RE_P = re.compile(r"(?:^|,)p=([^,]+)")  # client proof (base64)
_RE_C = re.compile(r"(?:^|,)c=([^,]+)")  # channel binding (base64)
_RE_GS2 = re.compile(r"^(?:n|y|p=[^,]*),,")  # GS2 header prefix


def _decode_scram_username(encoded: str) -> str:
    # RFC 5802: ',' → '=2C', '=' → '=3D'
    return encoded.replace("=2C", ",").replace("=3D", "=")


def _get_field(layer: BaseLayer, field_name: str):
    raw = layer._all_fields.get(field_name)
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(v) for v in raw]
    try:
        container = layer.get_field(field_name)
        return [f.show for f in container.all_fields]
    except Exception:
        return [str(raw)]


def _decode_bytes_field(layer: BaseLayer) -> str:
    raw = layer._all_fields.get("mongo.element.value.bytes", "")
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if not raw:
        return ""
    hex_str = getattr(raw, "raw_value", None) or str(raw).replace(":", "")
    try:
        return bytes.fromhex(hex_str).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return ""


def _get_conversation_id(layer: BaseLayer) -> str:
    raw = layer._all_fields.get("mongo.element.value.int")
    if raw is None:
        return "0"
    if isinstance(raw, list):
        return str(raw[0])
    return str(raw)


def analyse(session: Session, layer: BaseLayer):
    if not hasattr(layer, "opcode") or str(layer.opcode) != "2013":
        return

    element_names = _get_field(layer, "mongo.element.name")

    if "saslStart" in element_names:
        _handle_sasl_start(session, layer, element_names)
        return

    if "saslContinue" in element_names:
        _handle_sasl_continue(session, layer)
        return

    if "ok" in element_names and "payload" in element_names:
        _handle_server_reply(session, layer, element_names)


def _handle_sasl_start(session: Session, layer: BaseLayer, element_names):
    mechanism = next(
        (
            m
            for m in _get_field(layer, "mongo.element.value.string")
            if m in _SCRAM_MECHANISMS
        ),
        None,
    )
    if mechanism is None:
        logger.info(
            session, "MongoDB SASL authentication detected (unsupported mechanism)"
        )
        return

    payload = _decode_bytes_field(layer)
    if not payload:
        return

    user_match = _RE_N.search(payload)
    nonce_match = _RE_R.search(payload)
    if not user_match or not nonce_match:
        return

    username = _decode_scram_username(user_match.group(1))
    client_nonce = nonce_match.group(1)

    # Strip GS2 header to get client-first-message-bare for AuthMessage
    client_first_bare = _RE_GS2.sub("", payload, count=1)

    conv_id = _get_conversation_id(layer)
    if "_mongo_scram" not in session:
        session["_mongo_scram"] = {}

    session["_mongo_scram"][conv_id] = {
        "mechanism": mechanism,
        "username": username,
        "client_nonce": client_nonce,
        "client_first_bare": client_first_bare,
    }

    logger.info(session, "MongoDB {} authentication detected".format(mechanism))

    creds = session.credentials_being_built
    creds.username = username
    creds.context["mechanism"] = mechanism
    creds.context["client_nonce"] = client_nonce


def _handle_server_reply(session: Session, layer: BaseLayer, element_names):
    payload = _decode_bytes_field(layer)
    if not payload:
        return

    scram_sessions = session.get("_mongo_scram") or {}

    # server-first-message: r=<full_nonce>,s=<salt>,i=<iter>
    r_match = _RE_R.search(payload)
    s_match = _RE_S.search(payload)
    i_match = _RE_I.search(payload)

    if r_match and s_match and i_match:
        server_nonce = r_match.group(1)
        salt_b64 = s_match.group(1)
        iterations = i_match.group(1)

        # Match to the open conversation whose client_nonce prefixes server_nonce
        state = next(
            (
                v
                for v in scram_sessions.values()
                if server_nonce.startswith(v.get("client_nonce", "\x00"))
            ),
            None,
        )
        if state is None:
            return

        state["server_nonce"] = server_nonce
        state["salt_b64"] = salt_b64
        state["iterations"] = iterations
        state["server_first"] = payload

        creds = session.credentials_being_built
        creds.context["server_nonce"] = server_nonce
        creds.context["salt"] = salt_b64
        creds.context["iterations"] = iterations

        logger.info(
            session,
            "MongoDB SCRAM server-first — salt: {} | iterations: {} | server_nonce: {}".format(
                salt_b64, iterations, server_nonce
            ),
        )
        return

def _handle_sasl_continue(session: Session, layer: BaseLayer):
    payload = _decode_bytes_field(layer)
    if not payload:
        return

    scram_sessions = session.get("_mongo_scram") or {}

    r_match = _RE_R.search(payload)
    p_match = _RE_P.search(payload)
    c_match = _RE_C.search(payload)

    if not (r_match and p_match):
        return

    server_nonce = r_match.group(1)
    client_proof = p_match.group(1)
    channel_binding = c_match.group(1) if c_match else ""

    state = next(
        (v for v in scram_sessions.values() if v.get("server_nonce") == server_nonce),
        None,
    )
    if state is None:
        return

    # client-final-message-without-proof = c=<gs2>,r=<server_nonce>
    client_final_without_proof = "c={},r={}".format(channel_binding, server_nonce)

    # AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
    auth_message = "{},{},{}".format(
        state["client_first_bare"],
        state["server_first"],
        client_final_without_proof,
    )

    mechanism = state["mechanism"]
    username = state["username"]
    salt_b64 = state["salt_b64"]
    iterations = state["iterations"]

    creds = session.credentials_being_built
    creds.context["client_proof"] = client_proof
    creds.context["auth_message"] = auth_message

    logger.found(
        session,
        (
            "MongoDB credentials captured\n"
            "  USERNAME     : {}\n"
            "  MECHANISM    : {}\n"
            "  SALT         : {}\n"
            "  CLIENT_NONCE : {}\n"
            "  SERVER_NONCE : {}\n"
            "  ITERATIONS   : {}\n"
            "  TARGET       : {}"
        ).format(username, mechanism, salt_b64, state["client_nonce"], server_nonce, iterations, client_proof),
    )
    session.validate_credentials()
