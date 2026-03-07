#!/usr/bin/env python3
"""
Generate pcap sample files for the new authentication test cases.

Protocols covered:
  - IMAP  : AUTHENTICATE PLAIN, AUTHENTICATE LOGIN
  - POP3  : USER/PASS, AUTH LOGIN
  - SMTP  : AUTH CRAM-MD5
  - Kerberos: AS-REQ, AS-REP (roasting), TGS-REQ/TGS-REP (kerberoasting)

Run from the repo root:
    python3 tests/gen_pcaps.py
"""

import base64
import os

from scapy.all import wrpcap, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CLIENT_MAC = "aa:bb:cc:11:11:11"
SERVER_MAC = "aa:bb:cc:22:22:22"
CLIENT_IP = "192.168.10.1"
SERVER_IP = "192.168.10.2"

OUT_DIR = os.path.join(os.path.dirname(__file__), "samples")


def _tcp_session(client_port: int, server_port: int, exchanges: list) -> list:
    """
    Build a minimal TCP session (3-way handshake + data + FIN).

    exchanges: list of ("c2s" | "s2c", bytes)
    """
    pkts = []
    c_seq = 1000
    s_seq = 2000

    def c_eth():
        return Ether(src=CLIENT_MAC, dst=SERVER_MAC)

    def s_eth():
        return Ether(src=SERVER_MAC, dst=CLIENT_MAC)

    # SYN
    pkts.append(
        c_eth()
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=c_seq)
    )
    c_seq += 1

    # SYN-ACK
    pkts.append(
        s_eth()
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=server_port, dport=client_port, flags="SA", seq=s_seq, ack=c_seq)
    )
    s_seq += 1

    # ACK
    pkts.append(
        c_eth()
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq)
    )

    for direction, payload in exchanges:
        if direction == "c2s":
            pkts.append(
                c_eth()
                / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(
                    sport=client_port,
                    dport=server_port,
                    flags="PA",
                    seq=c_seq,
                    ack=s_seq,
                )
                / Raw(load=payload)
            )
            c_seq += len(payload)
            pkts.append(
                s_eth()
                / IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(
                    sport=server_port,
                    dport=client_port,
                    flags="A",
                    seq=s_seq,
                    ack=c_seq,
                )
            )
        else:
            pkts.append(
                s_eth()
                / IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(
                    sport=server_port,
                    dport=client_port,
                    flags="PA",
                    seq=s_seq,
                    ack=c_seq,
                )
                / Raw(load=payload)
            )
            s_seq += len(payload)
            pkts.append(
                c_eth()
                / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(
                    sport=client_port,
                    dport=server_port,
                    flags="A",
                    seq=c_seq,
                    ack=s_seq,
                )
            )

    # FIN
    pkts.append(
        c_eth()
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=client_port, dport=server_port, flags="FA", seq=c_seq, ack=s_seq)
    )
    return pkts


def save(name: str, pkts: list):
    path = os.path.join(OUT_DIR, name)
    wrpcap(path, pkts)
    print(f"  wrote {path}  ({len(pkts)} packets)")


# ---------------------------------------------------------------------------
# IMAP – AUTHENTICATE PLAIN   (port 143)
#   alice / s3cret
# ---------------------------------------------------------------------------
def gen_imap_authenticate_plain():
    sasl = base64.b64encode(b"\x00alice\x00s3cret").decode()
    exchanges = [
        ("s2c", b"* OK IMAP4rev1 Server ready\r\n"),
        ("c2s", b"a001 CAPABILITY\r\n"),
        ("s2c", b"* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\na001 OK\r\n"),
        ("c2s", b"a002 AUTHENTICATE PLAIN\r\n"),
        ("s2c", b"+ \r\n"),
        ("c2s", f"{sasl}\r\n".encode()),
        ("s2c", b"a002 OK AUTHENTICATE completed\r\n"),
    ]
    save("imap-authenticate-plain.pcap", _tcp_session(54100, 143, exchanges))


# ---------------------------------------------------------------------------
# IMAP – AUTHENTICATE LOGIN   (port 143)
#   charlie / p@ssw0rd
# ---------------------------------------------------------------------------
def gen_imap_authenticate_login():
    u_b64 = base64.b64encode(b"charlie").decode()
    p_b64 = base64.b64encode(b"p@ssw0rd").decode()
    exchanges = [
        ("s2c", b"* OK IMAP4rev1 Server ready\r\n"),
        ("c2s", b"a001 AUTHENTICATE LOGIN\r\n"),
        ("s2c", b"+ VXNlcm5hbWU6\r\n"),  # base64("Username:")
        ("c2s", f"{u_b64}\r\n".encode()),
        ("s2c", b"+ UGFzc3dvcmQ6\r\n"),  # base64("Password:")
        ("c2s", f"{p_b64}\r\n".encode()),
        ("s2c", b"a001 OK AUTHENTICATE completed\r\n"),
    ]
    save("imap-authenticate-login.pcap", _tcp_session(54101, 143, exchanges))


# ---------------------------------------------------------------------------
# POP3 – USER / PASS   (port 110)
#   alice / secret123
# ---------------------------------------------------------------------------
def gen_pop3_user_pass():
    exchanges = [
        ("s2c", b"+OK POP3 server ready\r\n"),
        ("c2s", b"USER alice\r\n"),
        ("s2c", b"+OK User accepted\r\n"),
        ("c2s", b"PASS secret123\r\n"),
        ("s2c", b"+OK Authentication successful, 0 messages\r\n"),
        ("c2s", b"QUIT\r\n"),
        ("s2c", b"+OK Bye\r\n"),
    ]
    save("pop3-user-pass.pcap", _tcp_session(54110, 110, exchanges))


# ---------------------------------------------------------------------------
# POP3 – AUTH LOGIN   (port 110)
#   frank / fr@nkpass
# ---------------------------------------------------------------------------
def gen_pop3_auth_login():
    u_b64 = base64.b64encode(b"frank").decode()
    p_b64 = base64.b64encode(b"fr@nkpass").decode()
    exchanges = [
        ("s2c", b"+OK POP3 server ready\r\n"),
        ("c2s", b"AUTH LOGIN\r\n"),
        ("s2c", b"+ VXNlcm5hbWU6\r\n"),
        ("c2s", f"{u_b64}\r\n".encode()),
        ("s2c", b"+ UGFzc3dvcmQ6\r\n"),
        ("c2s", f"{p_b64}\r\n".encode()),
        ("s2c", b"+OK Authentication succeeded\r\n"),
        ("c2s", b"QUIT\r\n"),
        ("s2c", b"+OK Bye\r\n"),
    ]
    save("pop3-auth-login.pcap", _tcp_session(54111, 110, exchanges))


# ---------------------------------------------------------------------------
# SMTP – AUTH CRAM-MD5   (port 25)
#   john  /  HMAC-MD5 hash = 3b4e5cdeadbeefcafe1234567890abcd
# ---------------------------------------------------------------------------
def gen_smtp_cram_md5():
    challenge = b"<1234.987@mailserver.example>"
    challenge_b64 = base64.b64encode(challenge).decode()
    # Client reply: base64("john 3b4e5cdeadbeefcafe1234567890abcd")
    cram_response = base64.b64encode(b"john 3b4e5cdeadbeefcafe1234567890abcd").decode()
    exchanges = [
        ("s2c", b"220 mailserver.example ESMTP\r\n"),
        ("c2s", b"EHLO client.example\r\n"),
        ("s2c", b"250-mailserver.example\r\n250-AUTH CRAM-MD5\r\n250 OK\r\n"),
        ("c2s", b"AUTH CRAM-MD5\r\n"),
        ("s2c", f"334 {challenge_b64}\r\n".encode()),
        ("c2s", f"{cram_response}\r\n".encode()),
        ("s2c", b"235 2.7.0 Authentication successful\r\n"),
    ]
    save("smtp-cram-md5.pcap", _tcp_session(54025, 25, exchanges))


# ---------------------------------------------------------------------------
# Shared Kerberos ASN.1 DER helpers
# ---------------------------------------------------------------------------

def _krb_helpers():
    """Returns a namespace of DER encoding helpers for Kerberos packets."""
    def der_len(n):
        if n < 0x80:
            return bytes([n])
        elif n < 0x100:
            return bytes([0x81, n])
        else:
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

    def tlv(tag, value):
        if isinstance(value, str):
            value = value.encode()
        return bytes([tag]) + der_len(len(value)) + value

    def seq(*items):
        body = b"".join(items)
        return tlv(0x30, body)

    def ctx(n, value):
        """Context-tagged [n] EXPLICIT wrapper."""
        return bytes([0xA0 | n]) + der_len(len(value)) + value

    def integer(n):
        """DER INTEGER — handles arbitrary positive integers."""
        if n == 0:
            return tlv(0x02, bytes([0]))
        # Convert to big-endian bytes, prepend 0x00 if high bit set
        length = (n.bit_length() + 7) // 8
        raw = n.to_bytes(length, 'big')
        if raw[0] & 0x80:
            raw = bytes([0x00]) + raw
        return tlv(0x02, raw)

    def gen_string(s):
        return tlv(0x1B, s.encode())  # GeneralString

    def octet_string(b):
        return tlv(0x04, b)

    def bit_string(b):
        """BIT STRING: first byte = number of unused bits (0)."""
        return tlv(0x03, bytes([0]) + b)

    def generalizedtime(s):
        return tlv(0x18, s.encode())

    def principal_name(name_type, names):
        """PrincipalName ::= SEQUENCE { name-type [0], name-string [1] SEQUENCE OF }"""
        name_strings = seq(*[gen_string(n) for n in names])
        return seq(
            ctx(0, integer(name_type)),
            ctx(1, name_strings),
        )

    class H:
        pass

    h = H()
    h.der_len = der_len
    h.tlv = tlv
    h.seq = seq
    h.ctx = ctx
    h.integer = integer
    h.gen_string = gen_string
    h.octet_string = octet_string
    h.bit_string = bit_string
    h.generalizedtime = generalizedtime
    h.principal_name = principal_name
    return h


def _build_ticket(h, realm, sname_names, etype=23):
    """Build minimal Ticket (APPLICATION 1 = 0x61) for embedding in KDC-REP."""
    tkt_enc = h.seq(h.ctx(0, h.integer(etype)), h.ctx(2, h.octet_string(b"\x00" * 8)))
    sname = h.principal_name(2, sname_names)
    ticket_inner = h.seq(
        h.ctx(0, h.integer(5)),          # tkt-vno [0]
        h.ctx(1, h.gen_string(realm)),    # realm [1]
        h.ctx(2, sname),                  # sname [2]
        h.ctx(3, tkt_enc),                # enc-part [3]
    )
    ticket_body = h.seq(ticket_inner)
    return bytes([0x61]) + h.der_len(len(ticket_body)) + ticket_body


# ---------------------------------------------------------------------------
# Kerberos – AS-REQ + AS-REP (AS-REP Roasting)   (UDP port 88)
#   principal: jdoe@CORP.LOCAL  /  cipher: deadbeefcafebabe12345678
# ---------------------------------------------------------------------------
def gen_kerberos_as_req_rep():
    """
    RFC 4120 compliant AS-REQ (msg_type=10) + AS-REP (msg_type=11).

    KDC-REQ-BODY field ordering (RFC 4120 §5.4.1):
      [0] kdc-options, [1] cname, [2] realm, [3] sname, [5] till, [7] nonce, [8] etype

    KDC-REP field ordering (RFC 4120 §5.4.2):
      [0] pvno, [1] msg-type, [3] crealm, [4] cname, [5] ticket, [6] enc-part
    """
    h = _krb_helpers()

    # -- AS-REQ (APPLICATION 10 = 0x6A) -------------------------------------
    # KDC-REQ-BODY
    kdc_opts = h.ctx(0, h.bit_string(bytes([0x00, 0x00, 0x00, 0x00])))
    cname    = h.ctx(1, h.principal_name(1, ["jdoe"]))
    realm    = h.ctx(2, h.gen_string("CORP.LOCAL"))
    sname    = h.ctx(3, h.principal_name(2, ["krbtgt", "CORP.LOCAL"]))
    till     = h.ctx(5, h.generalizedtime("19700101000000Z"))
    nonce    = h.ctx(7, h.integer(12345))
    etype    = h.ctx(8, h.seq(h.integer(23)))

    req_body_inner = h.seq(kdc_opts, cname, realm, sname, till, nonce, etype)
    req_body       = h.ctx(4, req_body_inner)

    as_req_seq = h.seq(h.ctx(1, h.integer(5)), h.ctx(2, h.integer(10)), req_body)
    as_req_der = bytes([0x6A]) + h.der_len(len(as_req_seq)) + as_req_seq

    as_req_pkt = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=54088, dport=88)
        / Raw(load=as_req_der)
    )

    # -- AS-REP (APPLICATION 11 = 0x6B) -------------------------------------
    cipher_bytes = bytes.fromhex("deadbeefcafebabe12345678")
    ticket = _build_ticket(h, "CORP.LOCAL", ["krbtgt", "CORP.LOCAL"])

    enc_part = h.ctx(6, h.seq(
        h.ctx(0, h.integer(23)),
        h.ctx(2, h.octet_string(cipher_bytes)),
    ))

    as_rep_seq = h.seq(
        h.ctx(0, h.integer(5)),                   # pvno [0]
        h.ctx(1, h.integer(11)),                  # msg-type [1]
        h.ctx(3, h.gen_string("CORP.LOCAL")),     # crealm [3]
        h.ctx(4, h.principal_name(1, ["jdoe"])),  # cname [4]
        h.ctx(5, ticket),                          # ticket [5]
        enc_part,                                  # enc-part [6]
    )
    as_rep_der = bytes([0x6B]) + h.der_len(len(as_rep_seq)) + as_rep_seq

    as_rep_pkt = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=88, dport=54088)
        / Raw(load=as_rep_der)
    )

    save("kerberos-as-req-rep.pcap", [as_req_pkt, as_rep_pkt])


# ---------------------------------------------------------------------------
# Kerberos – TGS-REQ + TGS-REP (Kerberoasting)   (UDP port 88)
#   requestor: jdoe@CORP.LOCAL  /  service: MSSQLSvc/db.corp.local:1433
#   cipher: aabbccddeeff001122334455
# ---------------------------------------------------------------------------
def gen_kerberos_tgs_req_rep():
    """
    RFC 4120 compliant TGS-REQ (msg_type=12) + TGS-REP (msg_type=13).

    TGS-REQ-BODY: same as AS-REQ-BODY but cname omitted, sname = service.
    TGS-REP: same KDC-REP structure, enc-part is service ticket cipher.
    """
    h = _krb_helpers()

    # -- TGS-REQ (APPLICATION 12 = 0x6C) ------------------------------------
    kdc_opts  = h.ctx(0, h.bit_string(bytes([0x00, 0x00, 0x00, 0x00])))
    realm_req = h.ctx(2, h.gen_string("CORP.LOCAL"))
    # sname for the service — use NT-SRV-HST (3) per RFC 4120
    sname_req = h.ctx(3, h.principal_name(3, ["MSSQLSvc/db.corp.local:1433"]))
    till_req  = h.ctx(5, h.generalizedtime("19700101000000Z"))
    nonce_req = h.ctx(7, h.integer(67890))
    etype_req = h.ctx(8, h.seq(h.integer(23)))

    req_body_inner = h.seq(kdc_opts, realm_req, sname_req, till_req, nonce_req, etype_req)
    req_body       = h.ctx(4, req_body_inner)

    tgs_req_seq = h.seq(h.ctx(1, h.integer(5)), h.ctx(2, h.integer(12)), req_body)
    tgs_req_der = bytes([0x6C]) + h.der_len(len(tgs_req_seq)) + tgs_req_seq

    tgs_req_pkt = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=54089, dport=88)
        / Raw(load=tgs_req_der)
    )

    # -- TGS-REP (APPLICATION 13 = 0x6D) ------------------------------------
    cipher_bytes = bytes.fromhex("aabbccddeeff001122334455")
    ticket_tgs = _build_ticket(h, "CORP.LOCAL", ["MSSQLSvc/db.corp.local:1433"])

    enc_part = h.ctx(6, h.seq(
        h.ctx(0, h.integer(23)),
        h.ctx(2, h.octet_string(cipher_bytes)),
    ))

    tgs_rep_seq = h.seq(
        h.ctx(0, h.integer(5)),                                       # pvno [0]
        h.ctx(1, h.integer(13)),                                      # msg-type [1]
        h.ctx(3, h.gen_string("CORP.LOCAL")),                         # crealm [3]
        h.ctx(4, h.principal_name(1, ["jdoe"])),                      # cname [4]
        h.ctx(5, ticket_tgs),                                          # ticket [5]
        enc_part,                                                       # enc-part [6]
    )
    tgs_rep_der = bytes([0x6D]) + h.der_len(len(tgs_rep_seq)) + tgs_rep_seq

    tgs_rep_pkt = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=88, dport=54089)
        / Raw(load=tgs_rep_der)
    )

    save("kerberos-tgs-req-rep.pcap", [tgs_req_pkt, tgs_rep_pkt])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Generating pcap samples...")
    gen_imap_authenticate_plain()
    gen_imap_authenticate_login()
    gen_pop3_user_pass()
    gen_pop3_auth_login()
    gen_smtp_cram_md5()
    gen_kerberos_as_req_rep()
    gen_kerberos_tgs_req_rep()
    print("Done.")
