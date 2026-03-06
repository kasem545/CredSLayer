# coding: utf-8

import os
import unittest

from pyshark import FileCapture

from credslayer.core import extract, utils
from credslayer.core.manager import process_pcap
from credslayer.core.session import Session
from credslayer.core.utils import Credentials, CreditCard


class ParsersTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_telnet(self):
        credentials_list = process_pcap("samples/telnet-cooked.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('fake', 'user') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/telnet-raw.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('fake', 'user') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/telnet-raw2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('Administrator', 'napier') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/telnet.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('shellcode', 'shellcode') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_ftp(self):
        credentials_list = process_pcap("samples/ftp.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('anonymous', 'ftp@example.com') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_smtp(self):
        credentials_list = process_pcap("samples/smtp.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('gurpartap@patriots.in', 'punjab@123') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_imap(self):
        credentials_list = process_pcap("samples/imap.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('neulingern', 'XXXXXX') in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_pop(self):
        credentials_list = process_pcap("samples/pop3.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('digitalinvestigator@networksims.com', 'napier123') in credentials_list)
        self.assertTrue(len(credentials_list) == 2)

    def test_http_basic_auth(self):
        credentials_list = process_pcap("samples/http-basic-auth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials('test', 'test') in credentials_list)
        self.assertFalse(Credentials('test', 'fail') in credentials_list)
        self.assertFalse(Credentials('test', 'fail2') in credentials_list)
        self.assertFalse(Credentials('test', 'fail3') in credentials_list)
        self.assertTrue(len(credentials_list) == 6)

    def test_http_post_auth(self):
        credentials_list = process_pcap("samples/http-post-auth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(
            Credentials(
                'toto',
                'Str0ngP4ssw0rd',
                context={'Method': 'POST', 'URL': 'http://192.168.56.101:1337/login'}
            ) in credentials_list
        )
        self.assertTrue(len(credentials_list) == 1)

    def test_http_get_auth(self):
        credentials_list = process_pcap("samples/http-get-auth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(
                Credentials(
                    'admin', 
                    'qwerty1234', 
                    context={'Method': 'GET', 'URL': 'http://192.168.56.101:1337/login?login=admin&password=qwerty1234'}
                ) in credentials_list
        )
        self.assertTrue(len(credentials_list) == 1)

    def test_ldap(self):
        credentials_list = process_pcap("samples/ldap-simpleauth.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("xxxxxxxxxxx@xx.xxx.xxxxx.net", "passwor8d1") in credentials_list)
        self.assertTrue(Credentials("CN=xxxxxxxx,OU=Users,OU=Accounts,DC=xx,"
                                    "DC=xxx,DC=xxxxx,DC=net", "/dev/rdsk/c0t0d0s0") in credentials_list)
        self.assertTrue(len(credentials_list) == 2)

    def test_snmp(self):
        credentials_list = process_pcap("samples/snmp-v1.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials(password="public") in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/snmp-v3.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials(username="pippo") in credentials_list)
        self.assertTrue(Credentials(username="pippo2") in credentials_list)
        self.assertTrue(Credentials(username="pippo3") in credentials_list)
        self.assertTrue(Credentials(username="pippo4") in credentials_list)
        self.assertTrue(len(credentials_list) == 4)

    def test_mysql(self):
        credentials_list = process_pcap("samples/mysql.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("tfoerste", hash="eefd6d5562851bc5966a0b41236ae3f2315efcc4",
                                    context={"salt": ">~$4uth,", "salt2": ">612IWZ>fhWX"}) in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

        credentials_list = process_pcap("samples/mysql2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("user10", hash="55ee72f0c6694cbb3a104eb97f8ee32a6a91f8b1",
                                    context={"salt": "]E!r<uX8", "salt2": "Of2c!tIM)\"n'"}) in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_mongodb_scram(self):
        credentials_list = process_pcap("samples/mongodb-scram.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(len(credentials_list) == 1)
        creds = credentials_list[0]
        self.assertEqual(creds.username, "alice")
        self.assertEqual(creds.context["mechanism"], "SCRAM-SHA-256")
        self.assertEqual(creds.context["salt"], "QSXCR+Q6sek8bf92")
        self.assertEqual(creds.context["client_nonce"], "fyko+d2lbbFgONRv9qkxdawL")
        self.assertEqual(creds.context["server_nonce"], "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j")
        self.assertEqual(creds.context["iterations"], "4096")
        self.assertEqual(creds.context["client_proof"], "FtNXbG+jbgSL8BU6f8mJ+wd/vOM0Tz1Wfhaq/mylRLM=")

    def test_pgsql(self):
        credentials_list = process_pcap("samples/pgsql.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("oryx", hash="ceffc01dcde7541829deef6b5e9c9142",
                                    context={"salt": "ad44ff54", "auth_type": "md5", "database": "mailstore"})
                        in credentials_list)
        self.assertTrue(Credentials("oryx", hash="f8f8b884b4ef7cc9ee95e69868cdfa5e",
                                    context={"salt": "f211a3ed", "auth_type": "md5", "database": "mailstore"})
                        in credentials_list)
        self.assertTrue(len(credentials_list) == 2)

        credentials_list = process_pcap("samples/pgsql-nopassword.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("user", context={"database": "dbdb"}) in credentials_list)
        self.assertTrue(len(credentials_list) == 1)

    def test_ntlmssp(self):
        credentials_list = process_pcap("samples/smb-ntlm.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(credentials_list == [Credentials(context={'version': 'NETNTLMv2'},
                                                         hash="Willi Wireshark::DESKTOP-2AEFM7G:78f8f6206e882559:8149b0"
                                                              "b2a73a191141bda07d1ed18434:01010000000000000bd7d7878527d"
                                                              "201146f94347775321c0000000002001e004400450053004b0054004"
                                                              "f0050002d00560031004600410030005500510001001e00440045005"
                                                              "3004b0054004f0050002d00560031004600410030005500510004001"
                                                              "e004400450053004b0054004f0050002d00560031004600410030005"
                                                              "500510003001e004400450053004b0054004f0050002d00560031004"
                                                              "6004100300055005100070008000bd7d7878527d2010600040002000"
                                                              "0000800300030000000000000000100000000200000ad865b6d08a95"
                                                              "d0e76a94e2ca013ab3f69c4fd945cca01b277700fd2b305ca010a001"
                                                              "00000000000000000000000000000000000090028006300690066007"
                                                              "3002f003100390032002e003100360038002e003100390039002e003"
                                                              "10033003300000000000000000000000000")])

        credentials_list = process_pcap("samples/smb-ntlm2.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(credentials_list == [Credentials(context={'version': 'NETNTLMv2'},
                                                         hash="administrator:::26de2c0b3abaaa1c:711d6cb05614bc240ca7e2a"
                                                              "38568ff85:0101000000000000e652e41aa7b4d401dac9a62e4db292"
                                                              "6b000000000200060046004f004f000100100044004600530052004f"
                                                              "004f00540031000400100066006f006f002e00740065007300740003"
                                                              "00220064006600730072006f006f00740031002e0066006f006f002e"
                                                              "0074006500730074000500100066006f006f002e0074006500730074"
                                                              "0007000800e652e41aa7b4d40100000000")])

        credentials_list = process_pcap("samples/smb-ntlm3.pcap").get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(credentials_list == [Credentials(context={'version': 'NETNTLMv1'},
                                                         hash="administrator::VNET3:42c09b264cbc46690000000000000000000"
                                                              "0000000000000:9cd7e4af2d7e934adc9b307231a958539b3d2c368b"
                                                              "964cea:28a3a326a53fa6f5")])

        remaining_credentials = process_pcap("samples/http-ntlm.pcap").get_remaining_content()
        remaining_credentials = [c[1] for c in remaining_credentials]  # Only get Credentials from the tuple

        print(remaining_credentials)

        self.assertTrue(len(remaining_credentials) == 6)
        self.assertTrue(Credentials(hash="administrator::example:ea46e3a07ea448d200000000000000000000000000000000:"
                                         "4d626ea83a02eee710571a2b84241788bd21e3a66ddbf4a5"
                                         ":CHALLENGE_NOT_FOUND", context={'version': 'NETNTLMv1'}) in remaining_credentials)


class ManagerTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_malformed(self):
        from credslayer.core import manager
        pcap = FileCapture("samples/smb-crash.pcap")
        self.assertRaises(manager.MalformedPacketException, manager._process_packet, Session(pcap[8]), pcap[8], False)
        pcap.close()

    def test_protocol_decode_as(self):
        from credslayer.core import manager
        credentials_list = manager.process_pcap("samples/telnet-hidden.pcap",
                                                decode_as={"tcp.port==1337": "telnet"}).get_list_of_all_credentials()
        print(credentials_list)
        self.assertTrue(Credentials("shellcode", "shellcode") in credentials_list)


class ExtractTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_extract_emails(self):
        pcap = FileCapture("samples/imap.pcap")
        emails_found = set()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            emails_found |= extract.extract_emails(strings)

        pcap.close()

        print(emails_found)

        self.assertTrue(len(emails_found) >= 46)
        self.assertTrue("nutmeg12s@hotmail.com" in emails_found)
        self.assertTrue("SharpJDs@yahoo.com" in emails_found)
        self.assertTrue("hardcase_890@yahoo.com" in emails_found)

        # TODO: make this one work... The thing is, the email address is splitted in 2 different packets... Give up ?
        # self.assertTrue("bandy_34@hotmail.com" in emails_found)

        pcap = FileCapture("samples/ldap-simpleauth.pcap")
        emails_found.clear()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            emails_found |= extract.extract_emails(strings)

        pcap.close()

        print(emails_found)

        self.assertTrue(len(emails_found) == 1)
        self.assertTrue("xxxxxxxxxxx@xx.xxx.xxxxx.net" in emails_found)

    def test_extract_credit_cards(self):
        pcap = FileCapture("samples/smtp-creditcards.pcap")

        credit_cards_found = set()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            credit_cards_found |= extract.extract_credit_cards(strings)

        pcap.close()

        print(credit_cards_found)

        self.assertTrue(CreditCard("Visa", "4111-4000-4321-3210") in credit_cards_found)
        self.assertTrue(CreditCard("Visa", "4321 4444 3214 3212") in credit_cards_found)
        self.assertTrue(CreditCard("Mastercard", "5555 5555 5555 5555") in credit_cards_found)

    def test_credit_cards_false_positives(self):
        pcap = FileCapture("samples/imap.pcap")
        credit_cards_found = set()

        for packet in pcap:
            strings = utils.extract_strings_splitted_on_end_of_line_from(packet)
            credit_cards_found |= extract.extract_credit_cards(strings)

        pcap.close()

        print(credit_cards_found)
        self.assertTrue(len(credit_cards_found) == 0)


class SessionsTest(unittest.TestCase):

    def setUp(self):
        # Set the working directory to the script's directory
        abspath = os.path.abspath(__file__)
        directory = os.path.dirname(abspath)
        os.chdir(directory)

    def test_sessions_extract(self):
        from credslayer.core.session import SessionsManager

        sessions = SessionsManager()

        pcap = FileCapture("samples/ftp.pcap")

        for packet in pcap:
            sessions.get_session_of(packet)

        pcap.close()

        print(sessions)
        self.assertTrue(len(sessions) == 1)
        self.assertTrue("TCP 10.10.30.26:43958 <-> 129.21.171.72:21" in sessions)

        sessions.clear()

        pcap = FileCapture("samples/imap.pcap")

        for packet in pcap:
            if "tcp" in packet:
                sessions.get_session_of(packet)

        pcap.close()

        print(sessions)
        self.assertTrue(len(sessions) == 3)
        self.assertTrue("TCP 131.151.32.21:4167 <-> 131.151.37.122:143" in sessions)
        self.assertTrue("TCP 131.151.32.91:3614 <-> 131.151.37.122:1065" in sessions)
        self.assertTrue("TCP 131.151.32.91:1065 <-> 131.151.37.117:1065" in sessions)

        sessions.clear()

        pcap = FileCapture("samples/snmp-v1.pcap")

        for packet in pcap:
            if "udp" in packet:
                sessions.get_session_of(packet)

        pcap.close()

        print(sessions)
        self.assertTrue(len(sessions) == 3)
        self.assertTrue("UDP 172.31.19.54 <-> 172.31.19.73" in sessions)
        self.assertTrue("UDP 172.31.19.73 <-> 224.0.1.35" in sessions)
        self.assertTrue("UDP 172.31.19.255 <-> 172.31.19.73" in sessions)

        # TODO: add more session tests


# ---------------------------------------------------------------------------
# Helpers shared by unit tests
# ---------------------------------------------------------------------------

class MockLayer:
    """Fake pyshark layer – set any attribute via keyword arguments."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockSession:
    """
    Minimal Session-like object that can be used without real pcap packets.
    Mirrors the dict API, validate/invalidate helpers, and credential tracking
    that parsers rely on.
    """
    def __init__(self):
        self._data = {}
        self.protocol = "tcp"
        self.credentials_being_built = utils.Credentials()
        self.credentials_list = []

    # --- dict-like interface (Session inherits dict) ---
    def __getitem__(self, item):
        return self._data.get(item, None)

    def __setitem__(self, name, value):
        self._data[name] = value

    def __contains__(self, item):
        return item in self._data

    def __repr__(self):
        return "MockSession"

    def clear(self):
        self._data.clear()

    # --- credential helpers ---
    def validate_credentials(self):
        self.credentials_list.append(self.credentials_being_built)
        self.credentials_being_built = utils.Credentials()

    def invalidate_credentials_and_clear_session(self):
        self._data.clear()
        self.credentials_being_built = utils.Credentials()


# ---------------------------------------------------------------------------
# IMAP – new authentication mechanisms
# ---------------------------------------------------------------------------

class ImapAuthTest(unittest.TestCase):
    """Unit tests for IMAP AUTHENTICATE PLAIN and LOGIN mechanisms."""

    def setUp(self):
        from credslayer.parsers import imap
        self.imap = imap

    # -- AUTHENTICATE PLAIN --------------------------------------------------

    def test_authenticate_plain_success(self):
        """AUTHENTICATE PLAIN: one-step SASL blob, server replies OK."""
        import base64
        session = MockSession()

        # C: A001 AUTHENTICATE PLAIN
        self.imap.analyse(session, MockLayer(request_command="AUTHENTICATE",
                                              request_parameter="PLAIN"))

        # C: <base64("\0alice\0s3cret")>
        sasl = base64.b64encode(b"\x00alice\x00s3cret").decode()
        self.imap.analyse(session, MockLayer(request_command=sasl))

        # S: A001 OK AUTHENTICATE completed
        self.imap.analyse(session, MockLayer(response="A001 OK AUTHENTICATE completed",
                                              response_status="OK"))

        self.assertEqual(len(session.credentials_list), 1)
        self.assertEqual(session.credentials_list[0].username, "alice")
        self.assertEqual(session.credentials_list[0].password, "s3cret")

    def test_authenticate_plain_failure(self):
        """AUTHENTICATE PLAIN: server replies NO → credentials must be discarded."""
        import base64
        session = MockSession()

        self.imap.analyse(session, MockLayer(request_command="AUTHENTICATE",
                                              request_parameter="PLAIN"))
        sasl = base64.b64encode(b"\x00bob\x00wrongpass").decode()
        self.imap.analyse(session, MockLayer(request_command=sasl))
        self.imap.analyse(session, MockLayer(response="A001 NO Authentication failed",
                                              response_status="NO"))

        self.assertEqual(len(session.credentials_list), 0)
        self.assertIsNone(session.credentials_being_built.username)

    # -- AUTHENTICATE LOGIN --------------------------------------------------

    def test_authenticate_login_success(self):
        """AUTHENTICATE LOGIN: two-step base64 challenge, server replies OK."""
        import base64
        session = MockSession()

        # C: A001 AUTHENTICATE LOGIN
        self.imap.analyse(session, MockLayer(request_command="AUTHENTICATE",
                                              request_parameter="LOGIN"))

        # S: + VXNlcm5hbWU=  (server sends 'Username' challenge, client replies)
        # C: <base64('charlie')>
        self.imap.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"charlie").decode()))

        # C: <base64('p@ssw0rd')>
        self.imap.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"p@ssw0rd").decode()))

        # S: A001 OK AUTHENTICATE completed
        self.imap.analyse(session, MockLayer(response="A001 OK AUTHENTICATE completed",
                                              response_status="OK"))

        self.assertEqual(len(session.credentials_list), 1)
        self.assertEqual(session.credentials_list[0].username, "charlie")
        self.assertEqual(session.credentials_list[0].password, "p@ssw0rd")

    def test_authenticate_login_failure(self):
        """AUTHENTICATE LOGIN: server replies BAD → credentials discarded."""
        import base64
        session = MockSession()

        self.imap.analyse(session, MockLayer(request_command="AUTHENTICATE",
                                              request_parameter="LOGIN"))
        self.imap.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"dave").decode()))
        self.imap.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"badpass").decode()))
        self.imap.analyse(session, MockLayer(response="A001 BAD Authentication failed",
                                              response_status="BAD"))

        self.assertEqual(len(session.credentials_list), 0)

    # -- existing plain LOGIN still works ------------------------------------

    def test_plain_login_still_works(self):
        """Ensure the original plaintext LOGIN command is not broken."""
        session = MockSession()
        # Plaintext: A001 LOGIN "user" "pass" — tshark splits into three quoted tokens
        self.imap.analyse(session, MockLayer(request_command="LOGIN",
                                              request='A001 LOGIN "neulingern" "XXXXXX"'))
        self.imap.analyse(session, MockLayer(response="A001 OK LOGIN completed",
                                              response_status="OK"))

        self.assertEqual(len(session.credentials_list), 1)
        self.assertEqual(session.credentials_list[0].username, "neulingern")
        self.assertEqual(session.credentials_list[0].password, "XXXXXX")


# ---------------------------------------------------------------------------
# POP3 – USER/PASS and AUTH LOGIN
# ---------------------------------------------------------------------------

class Pop3AuthTest(unittest.TestCase):
    """Unit tests for POP3 USER/PASS command flow and AUTH LOGIN mechanism."""

    def setUp(self):
        from credslayer.parsers import pop
        self.pop = pop

    # -- USER / PASS ---------------------------------------------------------

    def test_user_pass_success(self):
        """Standard POP3 USER/PASS flow — successful login."""
        session = MockSession()

        # C: USER alice
        self.pop.analyse(session, MockLayer(request_command="USER",
                                             request_parameter="alice"))
        # S: +OK User accepted
        self.pop.analyse(session, MockLayer(response_indicator="+OK"))

        # C: PASS secret123
        self.pop.analyse(session, MockLayer(request_command="PASS",
                                             request_parameter="secret123"))
        # S: +OK Pass accepted – authentication succeeded
        self.pop.analyse(session, MockLayer(response_indicator="+OK"))

        self.assertEqual(len(session.credentials_list), 1)
        self.assertEqual(session.credentials_list[0].username, "alice")
        self.assertEqual(session.credentials_list[0].password, "secret123")

    def test_user_pass_failed(self):
        """POP3 USER/PASS flow — wrong password, -ERR from server."""
        session = MockSession()

        self.pop.analyse(session, MockLayer(request_command="USER",
                                             request_parameter="alice"))
        self.pop.analyse(session, MockLayer(response_indicator="+OK"))
        self.pop.analyse(session, MockLayer(request_command="PASS",
                                             request_parameter="wrongpass"))
        self.pop.analyse(session, MockLayer(response_indicator="-ERR"))

        self.assertEqual(len(session.credentials_list), 0)
        self.assertIsNone(session.credentials_being_built.username)

    def test_user_ok_does_not_validate(self):
        """The +OK after USER must not trigger credential validation."""
        session = MockSession()

        self.pop.analyse(session, MockLayer(request_command="USER",
                                             request_parameter="eve"))
        # Server acknowledges USER — this must NOT create a credential entry
        self.pop.analyse(session, MockLayer(response_indicator="+OK"))

        self.assertEqual(len(session.credentials_list), 0)
        self.assertEqual(session.credentials_being_built.username, "eve")

    # -- AUTH LOGIN ----------------------------------------------------------

    def test_auth_login_success(self):
        """POP3 AUTH LOGIN: two-step base64 challenge/response, server +OK."""
        import base64
        session = MockSession()

        # C: AUTH LOGIN
        self.pop.analyse(session, MockLayer(request_command="AUTH",
                                             request_parameter="LOGIN"))

        # S: + VXNlcm5hbWU=  (challenge: 'Username')
        # C: <base64('frank')>
        self.pop.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"frank").decode()))

        # C: <base64('fr@nkpass')>
        self.pop.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"fr@nkpass").decode()))

        # S: +OK Authentication succeeded
        self.pop.analyse(session, MockLayer(response_indicator="+OK"))

        self.assertEqual(len(session.credentials_list), 1)
        self.assertEqual(session.credentials_list[0].username, "frank")
        self.assertEqual(session.credentials_list[0].password, "fr@nkpass")

    def test_auth_login_failure(self):
        """POP3 AUTH LOGIN: server responds -ERR → credentials discarded."""
        import base64
        session = MockSession()

        self.pop.analyse(session, MockLayer(request_command="AUTH",
                                             request_parameter="LOGIN"))
        self.pop.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"grace").decode()))
        self.pop.analyse(session,
                          MockLayer(request_command=base64.b64encode(b"badpass").decode()))
        self.pop.analyse(session, MockLayer(response_indicator="-ERR"))

        self.assertEqual(len(session.credentials_list), 0)

    # -- existing AUTH PLAIN still works ------------------------------------

    def test_auth_plain_still_works(self):
        """Ensure the existing AUTH PLAIN mechanism is not broken."""
        import base64
        session = MockSession()

        self.pop.analyse(session, MockLayer(request_command="AUTH",
                                             request_parameter="PLAIN"))
        sasl = base64.b64encode(b"\x00henry\x00h3nrypass").decode()
        self.pop.analyse(session, MockLayer(request_command=sasl))
        self.pop.analyse(session, MockLayer(response_indicator="+OK"))

        self.assertEqual(len(session.credentials_list), 1)
        self.assertEqual(session.credentials_list[0].username, "henry")
        self.assertEqual(session.credentials_list[0].password, "h3nrypass")


# ---------------------------------------------------------------------------
# SMTP – AUTH CRAM-MD5
# ---------------------------------------------------------------------------

class SmtpAuthCramMd5Test(unittest.TestCase):
    """Unit tests for SMTP AUTH CRAM-MD5 mechanism."""

    def setUp(self):
        from credslayer.parsers import smtp
        self.smtp = smtp

    def test_auth_cram_md5_success(self):
        """
        AUTH CRAM-MD5 flow:
          C: AUTH CRAM-MD5
          S: 334 <base64-challenge>
          C: <base64('username HMAC-MD5-hex')>
          S: 235 Authentication successful
        Credentials must contain username and the HMAC-MD5 hash.
        """
        import base64
        session = MockSession()

        challenge = b"<1234.987@mailserver.example>"
        challenge_b64 = base64.b64encode(challenge).decode()

        # C: AUTH CRAM-MD5
        self.smtp.analyse(session, MockLayer(req_command="AUTH",
                                              req_parameter="CRAM-MD5"))

        # S: 334 <base64-challenge>
        self.smtp.analyse(session, MockLayer(response_code="334",
                                              response_parameter=challenge_b64))

        # C: <base64('john 3b4e5c...')>   (username + space + HMAC-MD5 hex)
        cram_response = base64.b64encode(b"john 3b4e5cdeadbeefcafe1234567890ab").decode()
        self.smtp.analyse(session, MockLayer(req_command=cram_response))

        # S: 235
        self.smtp.analyse(session, MockLayer(response_code="235"))

        self.assertEqual(len(session.credentials_list), 1)
        creds = session.credentials_list[0]
        self.assertEqual(creds.username, "john")
        self.assertIsNotNone(creds.hash)
        self.assertIn("3b4e5cdeadbeefcafe1234567890ab", creds.hash)

    def test_auth_cram_md5_failure(self):
        """AUTH CRAM-MD5 with 535 response must discard credentials."""
        import base64
        session = MockSession()

        challenge_b64 = base64.b64encode(b"<9999@host>").decode()

        self.smtp.analyse(session, MockLayer(req_command="AUTH",
                                              req_parameter="CRAM-MD5"))
        self.smtp.analyse(session, MockLayer(response_code="334",
                                              response_parameter=challenge_b64))
        cram_response = base64.b64encode(b"ivan badhmac").decode()
        self.smtp.analyse(session, MockLayer(req_command=cram_response))
        self.smtp.analyse(session, MockLayer(response_code="535"))

        self.assertEqual(len(session.credentials_list), 0)


# ---------------------------------------------------------------------------
# Kerberos – AS-REQ / AS-REP Roasting / Kerberoasting
# ---------------------------------------------------------------------------

class KerberosParserTest(unittest.TestCase):
    """
    Unit tests for the Kerberos parser.
    All layers are mocked because we have no Kerberos pcap sample.
    """

    def setUp(self):
        from credslayer.parsers import kerberos
        self.kerberos = kerberos

    # -- AS-REQ: username extraction -----------------------------------------

    def test_as_req_extracts_username(self):
        """AS-REQ (msg_type=10) must record the requesting username in the session."""
        session = MockSession()
        layer = MockLayer(
            msg_type="10",
            realm="CORP.LOCAL",
            cname_name_string="jdoe",
        )
        self.kerberos.analyse(session, layer)

        self.assertEqual(session["krb_username"], "jdoe")
        self.assertEqual(session["krb_realm"], "CORP.LOCAL")

    # -- AS-REP Roasting -----------------------------------------------------

    def test_as_rep_roasting(self):
        """
        AS-REP (msg_type=11) for an account without pre-auth must produce a
        $krb5asrep$ hash suitable for offline cracking.
        """
        session = MockSession()
        session["krb_username"] = "svc_nopreauth"
        session["krb_realm"] = "CORP.LOCAL"

        layer = MockLayer(
            msg_type="11",
            realm="CORP.LOCAL",
            etype="23",
            cipher="deadbeef:cafebabe:12345678",
        )
        self.kerberos.analyse(session, layer)

        self.assertEqual(len(session.credentials_list), 1)
        creds = session.credentials_list[0]
        self.assertEqual(creds.username, "svc_nopreauth")
        self.assertIsNotNone(creds.hash)
        self.assertTrue(creds.hash.startswith("$krb5asrep$"))
        self.assertIn("svc_nopreauth", creds.hash)
        self.assertIn("CORP.LOCAL", creds.hash)
        self.assertIn("deadbeefcafebabe12345678", creds.hash)
        self.assertEqual(creds.context["Type"], "AS-REP Roasting")

    # -- Kerberoasting (TGS-REP) ---------------------------------------------

    def test_tgs_rep_kerberoasting(self):
        """
        TGS-REP (msg_type=13) must produce a $krb5tgs$ hash for the service
        ticket, which can be cracked offline to recover the service account
        password.
        """
        session = MockSession()
        session["krb_username"] = "jdoe"
        session["krb_realm"] = "CORP.LOCAL"
        session["krb_sname"] = "MSSQLSvc/dbserver.corp.local:1433"

        layer = MockLayer(
            msg_type="13",
            realm="CORP.LOCAL",
            etype="23",
            cipher="aabbccdd:eeff0011:22334455",
        )
        self.kerberos.analyse(session, layer)

        self.assertEqual(len(session.credentials_list), 1)
        creds = session.credentials_list[0]
        self.assertIsNotNone(creds.hash)
        self.assertTrue(creds.hash.startswith("$krb5tgs$"))
        self.assertIn("MSSQLSvc/dbserver.corp.local:1433", creds.hash)
        self.assertIn("CORP.LOCAL", creds.hash)
        self.assertIn("aabbccddeeff001122334455", creds.hash)
        self.assertEqual(creds.context["Type"], "Kerberoasting")

    def test_tgs_req_stores_sname(self):
        """TGS-REQ (msg_type=12) must store the requested service name for context."""
        session = MockSession()
        layer = MockLayer(
            msg_type="12",
            sname_name_string="HTTP/webapp.corp.local",
        )
        self.kerberos.analyse(session, layer)

        self.assertEqual(session["krb_sname"], "HTTP/webapp.corp.local")


if __name__ == '__main__':
    unittest.main()
