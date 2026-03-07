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
# pcap-based integration tests for new authentication mechanisms
# ---------------------------------------------------------------------------


class ImapAuthIntegrationTest(unittest.TestCase):
    """Integration tests for IMAP AUTHENTICATE PLAIN and LOGIN mechanisms."""

    def setUp(self):
        abspath = os.path.abspath(__file__)
        os.chdir(os.path.dirname(abspath))

    def test_authenticate_plain(self):
        """AUTHENTICATE PLAIN: alice / s3cret extracted from real pcap."""
        credentials_list = process_pcap("samples/imap-authenticate-plain.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        self.assertTrue(Credentials('alice', 's3cret') in credentials_list)

    def test_authenticate_login(self):
        """AUTHENTICATE LOGIN: charlie / p@ssw0rd extracted from real pcap."""
        credentials_list = process_pcap("samples/imap-authenticate-login.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        self.assertTrue(Credentials('charlie', 'p@ssw0rd') in credentials_list)


class Pop3AuthIntegrationTest(unittest.TestCase):
    """Integration tests for POP3 USER/PASS and AUTH LOGIN mechanisms."""

    def setUp(self):
        abspath = os.path.abspath(__file__)
        os.chdir(os.path.dirname(abspath))

    def test_user_pass(self):
        """POP3 USER/PASS: alice / secret123 extracted from real pcap."""
        credentials_list = process_pcap("samples/pop3-user-pass.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        self.assertTrue(Credentials('alice', 'secret123') in credentials_list)

    def test_auth_login(self):
        """POP3 AUTH LOGIN: frank / fr@nkpass extracted from real pcap."""
        credentials_list = process_pcap("samples/pop3-auth-login.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        self.assertTrue(Credentials('frank', 'fr@nkpass') in credentials_list)


class SmtpCramMd5IntegrationTest(unittest.TestCase):
    """Integration test for SMTP AUTH CRAM-MD5 mechanism."""

    def setUp(self):
        abspath = os.path.abspath(__file__)
        os.chdir(os.path.dirname(abspath))

    def test_auth_cram_md5(self):
        """AUTH CRAM-MD5: john with HMAC-MD5 hash extracted from real pcap."""
        credentials_list = process_pcap("samples/smtp-cram-md5.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        creds = credentials_list[0]
        self.assertEqual(creds.username, 'john')
        self.assertIsNotNone(creds.hash)
        self.assertIn('3b4e5cdeadbeefcafe1234567890abcd', creds.hash)
        self.assertEqual(creds.context.get('Mechanism'), 'CRAM-MD5')


class KerberosIntegrationTest(unittest.TestCase):
    """Integration tests for Kerberos AS-REP Roasting and Kerberoasting."""

    def setUp(self):
        abspath = os.path.abspath(__file__)
        os.chdir(os.path.dirname(abspath))

    def test_as_rep_roasting(self):
        """
        AS-REQ + AS-REP: jdoe@CORP.LOCAL AS-REP Roasting hash extracted.
        Hash format: $krb5asrep$<etype>$<username>@<REALM>:<checksum>$<enc_data>
        Cipher is from KDC-REP.enc-part (ciphers[-1] in stream order).
        checksum = first 16 bytes (32 hex chars), enc_data = remainder.
        """
        credentials_list = process_pcap("samples/kerberos-as-req-rep.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        creds = credentials_list[0]
        self.assertEqual(creds.username, 'jdoe')
        self.assertTrue(creds.hash.startswith('$krb5asrep$'))
        self.assertIn('jdoe', creds.hash)
        self.assertIn('CORP.LOCAL', creds.hash)
        # cipher hex = deadbeefcafebabe12345678aabbccdd001122334455
        # checksum   = deadbeefcafebabe12345678aabbccdd  (first 32 hex chars)
        # enc_data   = 001122334455
        self.assertIn('deadbeefcafebabe12345678', creds.hash)   # substring of checksum
        self.assertIn('001122334455', creds.hash)               # enc_data
        self.assertEqual(creds.context.get('Type'), 'AS-REP Roasting')

    def test_tgs_rep_kerberoasting(self):
        """
        TGS-REQ + TGS-REP: Kerberoasting hash for MSSQLSvc service extracted.
        Hash format: $krb5tgs$<etype>$*<username>$<REALM>$<service>*$<checksum>$<enc_data>
        Cipher is from Ticket.enc-part (ciphers[0] in stream order).
        """
        credentials_list = process_pcap("samples/kerberos-tgs-req-rep.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        creds = credentials_list[0]
        self.assertTrue(creds.hash.startswith('$krb5tgs$'))
        self.assertIn('MSSQLSvc/db.corp.local:1433', creds.hash)
        self.assertIn('CORP.LOCAL', creds.hash)
        # cipher hex = aabbccddeeff001122334455667788ff001122334455
        # checksum   = aabbccddeeff001122334455667788ff  (first 32 hex chars)
        # enc_data   = 001122334455
        self.assertIn('aabbccddeeff001122334455', creds.hash)  # substring of checksum
        self.assertIn('001122334455', creds.hash)              # enc_data
        self.assertEqual(creds.context.get('Type'), 'Kerberoasting')

    def test_as_req_preauth(self):
        """
        AS-REQ with PA-ENC-TIMESTAMP: pre-auth hash extracted.
        Hash format: $krb5pa$<etype>$<username>$<REALM>$<cipher>
        (Hashcat mode 19900)
        """
        credentials_list = process_pcap("samples/kerberos-as-req-preauth.pcap").get_list_of_all_credentials()
        self.assertEqual(len(credentials_list), 1)
        creds = credentials_list[0]
        self.assertEqual(creds.username, 'jdoe')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('18', creds.hash)                             # etype AES256
        self.assertIn('jdoe', creds.hash)
        self.assertIn('CORP.LOCAL', creds.hash)
        self.assertIn('aabbccddeeff001122334455', creds.hash)       # substring of cipher
        self.assertEqual(creds.context.get('Type'), 'AS-REQ Pre-auth')



class KerberosRealPcapKrb5Test(unittest.TestCase):
    """
    Integration tests against the real-world Samba KDC capture (krb5.pcap).

    The capture contains three principals in SAMBA.EXAMPLE.COM:
      - LOCALDC$       : AS-REQ Pre-auth + AS-REP Roasting
      - Administrator  : AS-REQ Pre-auth + AS-REP Roasting + Kerberoasting (ldap SPN)
      - LOCALADMEMBER$ : AS-REQ Pre-auth + AS-REP Roasting + Kerberoasting (ldap SPN)
    """

    def setUp(self):
        abspath = os.path.abspath(__file__)
        os.chdir(os.path.dirname(abspath))
        self.credentials_list = process_pcap('samples/krb5.pcap').get_list_of_all_credentials()
        self.krb_creds = [c for c in self.credentials_list if c.context.get('Type') in
                          ('AS-REQ Pre-auth', 'AS-REP Roasting', 'Kerberoasting')]

    def _find(self, username, hash_type):
        """Return the first credential matching (username, hash_type), or None."""
        for c in self.krb_creds:
            if c.username == username and c.context.get('Type') == hash_type:
                return c
        return None

    # ------------------------------------------------------------------
    # LOCALDC$ principal
    # ------------------------------------------------------------------

    def test_localdc_as_req_preauth(self):
        """LOCALDC$ AS-REQ Pre-auth hash extracted with correct format."""
        creds = self._find('LOCALDC$', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'LOCALDC$ AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'),
                        f'Unexpected hash prefix: {creds.hash[:20]}')
        self.assertIn('LOCALDC$', creds.hash)
        self.assertIn('SAMBA.EXAMPLE.COM', creds.hash)
        self.assertEqual(creds.context['Realm'], 'SAMBA.EXAMPLE.COM')
        self.assertEqual(creds.context['Type'], 'AS-REQ Pre-auth')

    def test_localdc_as_rep_roasting(self):
        """LOCALDC$ AS-REP Roasting hash extracted with correct format."""
        creds = self._find('LOCALDC$', 'AS-REP Roasting')
        self.assertIsNotNone(creds, 'LOCALDC$ AS-REP Roasting not found')
        self.assertTrue(creds.hash.startswith('$krb5asrep$'),
                        f'Unexpected hash prefix: {creds.hash[:20]}')
        self.assertIn('LOCALDC$@SAMBA.EXAMPLE.COM', creds.hash)
        self.assertEqual(creds.context['Type'], 'AS-REP Roasting')
        # checksum:enc_data separator must be present
        self.assertIn(':', creds.hash[creds.hash.index('$', 11):])

    # ------------------------------------------------------------------
    # Administrator principal
    # ------------------------------------------------------------------

    def test_administrator_as_req_preauth(self):
        """Administrator AS-REQ Pre-auth hash extracted."""
        creds = self._find('Administrator', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'Administrator AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('Administrator', creds.hash)
        self.assertIn('SAMBA.EXAMPLE.COM', creds.hash)

    def test_administrator_as_rep_roasting(self):
        """Administrator AS-REP Roasting hash extracted."""
        creds = self._find('Administrator', 'AS-REP Roasting')
        self.assertIsNotNone(creds, 'Administrator AS-REP Roasting not found')
        self.assertTrue(creds.hash.startswith('$krb5asrep$'))
        self.assertIn('Administrator@SAMBA.EXAMPLE.COM', creds.hash)

    def test_administrator_kerberoasting(self):
        """Administrator Kerberoasting hash extracted (krbtgt SPN in this capture)."""
        creds = self._find('Administrator', 'Kerberoasting')
        self.assertIsNotNone(creds, 'Administrator Kerberoasting not found')
        self.assertTrue(creds.hash.startswith('$krb5tgs$'),
                        f'Unexpected hash prefix: {creds.hash[:20]}')
        self.assertIn('Administrator', creds.hash)
        self.assertIn('SAMBA.EXAMPLE.COM', creds.hash)
        self.assertEqual(creds.context['Type'], 'Kerberoasting')
        # hash must contain $<checksum>$<enc_data> section
        self.assertGreater(creds.hash.count('$'), 4)

    # ------------------------------------------------------------------
    # LOCALADMEMBER$ principal
    # ------------------------------------------------------------------

    def test_localadmember_as_req_preauth(self):
        """LOCALADMEMBER$ AS-REQ Pre-auth hash extracted."""
        creds = self._find('LOCALADMEMBER$', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'LOCALADMEMBER$ AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('LOCALADMEMBER$', creds.hash)
        self.assertIn('SAMBA.EXAMPLE.COM', creds.hash)

    def test_localadmember_as_rep_roasting(self):
        """LOCALADMEMBER$ AS-REP Roasting hash extracted."""
        creds = self._find('LOCALADMEMBER$', 'AS-REP Roasting')
        self.assertIsNotNone(creds, 'LOCALADMEMBER$ AS-REP Roasting not found')
        self.assertTrue(creds.hash.startswith('$krb5asrep$'))
        self.assertIn('LOCALADMEMBER$@SAMBA.EXAMPLE.COM', creds.hash)

    def test_localadmember_kerberoasting(self):
        """LOCALADMEMBER$ Kerberoasting hash extracted."""
        creds = self._find('LOCALADMEMBER$', 'Kerberoasting')
        self.assertIsNotNone(creds, 'LOCALADMEMBER$ Kerberoasting not found')
        self.assertTrue(creds.hash.startswith('$krb5tgs$'))
        self.assertIn('LOCALADMEMBER$', creds.hash)
        self.assertIn('SAMBA.EXAMPLE.COM', creds.hash)
        self.assertEqual(creds.context['Type'], 'Kerberoasting')


class KerberosRealPcapKrb5v2Test(unittest.TestCase):
    """
    Integration tests against the mixed Kerberos capture (KRB5-2.pcap).

    Notable principals in this capture:
      - lulu@EXAMPLE.COM                            : AS-REP Roasting (etype 23 + 18) + AS-REQ Pre-auth
      - choppydog@PICKLESWORTH                      : AS-REQ Pre-auth
      - vladg@VLADG.NET                             : Kerberoasting (krbtgt service)
      - valid_client_principal@VLADG.NET            : AS-REP Roasting
      - requires_preauth_client_principal@VLADG.NET : AS-REQ Pre-auth + AS-REP Roasting
      - lockout_policy_client_principal@VLADG.NET   : AS-REQ Pre-auth
    """

    def setUp(self):
        abspath = os.path.abspath(__file__)
        os.chdir(os.path.dirname(abspath))
        self.credentials_list = process_pcap('samples/KRB5-2.pcap').get_list_of_all_credentials()
        self.krb_creds = [c for c in self.credentials_list if c.context.get('Type') in
                          ('AS-REQ Pre-auth', 'AS-REP Roasting', 'Kerberoasting')]

    def _find(self, username, hash_type):
        for c in self.krb_creds:
            if c.username == username and c.context.get('Type') == hash_type:
                return c
        return None

    def test_lulu_as_rep_roasting(self):
        """lulu@EXAMPLE.COM AS-REP Roasting hash extracted."""
        creds = self._find('lulu', 'AS-REP Roasting')
        self.assertIsNotNone(creds, 'lulu AS-REP Roasting not found')
        self.assertTrue(creds.hash.startswith('$krb5asrep$'))
        self.assertIn('lulu@EXAMPLE.COM', creds.hash)
        self.assertEqual(creds.context['Type'], 'AS-REP Roasting')
        # checksum:enc_data split must be present
        colon_pos = creds.hash.find(':')
        self.assertGreater(colon_pos, 0)

    def test_lulu_as_req_preauth(self):
        """lulu@EXAMPLE.COM AS-REQ Pre-auth hash extracted."""
        creds = self._find('lulu', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'lulu AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('lulu', creds.hash)
        self.assertIn('EXAMPLE.COM', creds.hash)

    def test_choppydog_as_req_preauth(self):
        """choppydog@PICKLESWORTH AS-REQ Pre-auth hash extracted (AES256)."""
        creds = self._find('choppydog', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'choppydog AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('choppydog', creds.hash)
        self.assertIn('PICKLESWORTH', creds.hash)
        self.assertEqual(creds.context['EType'], '18')   # AES256

    def test_vladg_kerberoasting(self):
        """vladg@VLADG.NET Kerberoasting hash extracted."""
        creds = self._find('vladg', 'Kerberoasting')
        self.assertIsNotNone(creds, 'vladg Kerberoasting not found')
        self.assertTrue(creds.hash.startswith('$krb5tgs$'))
        self.assertIn('vladg', creds.hash)
        self.assertIn('VLADG.NET', creds.hash)
        self.assertEqual(creds.context['Type'], 'Kerberoasting')

    def test_valid_client_principal_as_rep_roasting(self):
        """valid_client_principal@VLADG.NET AS-REP Roasting hash extracted."""
        creds = self._find('valid_client_principal', 'AS-REP Roasting')
        self.assertIsNotNone(creds, 'valid_client_principal AS-REP Roasting not found')
        self.assertTrue(creds.hash.startswith('$krb5asrep$'))
        self.assertIn('valid_client_principal@VLADG.NET', creds.hash)
        # Must have checksum:enc_data structure after the realm
        self.assertIn(':', creds.hash)

    def test_requires_preauth_principal_preauth(self):
        """requires_preauth_client_principal AS-REQ Pre-auth hash extracted."""
        creds = self._find('requires_preauth_client_principal', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'requires_preauth_client_principal AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('requires_preauth_client_principal', creds.hash)
        self.assertIn('VLADG.NET', creds.hash)

    def test_lockout_policy_principal_preauth(self):
        """lockout_policy_client_principal AS-REQ Pre-auth hash extracted."""
        creds = self._find('lockout_policy_client_principal', 'AS-REQ Pre-auth')
        self.assertIsNotNone(creds, 'lockout_policy_client_principal AS-REQ Pre-auth not found')
        self.assertTrue(creds.hash.startswith('$krb5pa$'))
        self.assertIn('lockout_policy_client_principal', creds.hash)
        self.assertIn('VLADG.NET', creds.hash)

if __name__ == '__main__':
    unittest.main()
