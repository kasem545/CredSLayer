# coding: utf-8

import base64
import json
import re
from urllib.parse import parse_qs

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session
from credslayer.core.utils import Credentials
from credslayer.core.file_extractor import get_file_extractor

HTTP_IGNORED_EXTENSIONS = ["css", "ico", "png", "jpg", "jpeg", "gif", "js"]
HTTP_METHODS = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]

HTTP_AUTH_MAX_LOGIN_POST_LENGTH = 500  # We ignore every posted content exceeding that length to prevent false positives
HTTP_AUTH_POTENTIAL_USERNAMES = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                                 'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname',
                                 'loginname', 'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login',
                                 'user_id', 'screename', 'uname', 'ulogin', 'acctname', 'account', 'member',
                                 'mailaddress', 'membername', 'login_username', 'login_email', 'loginusername',
                                 'loginemail', 'sign-in', 'j_username']

HTTP_AUTH_POTENTIAL_PASSWORDS = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password',
                                 'sessionpassword', 'login_password', 'loginpassword', 'form_pw', 'userpassword',
                                 'upassword', 'login_password', 'passwort', 'passwrd', 'wppassword', 'upasswd',
                                 'j_password', 'pwd', 'passphrase', 'secret']

# API key patterns
HTTP_API_KEY_PATTERNS = [
    re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE),
    re.compile(r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.IGNORECASE),
    re.compile(r'authorization["\']?\s*[:=]\s*["\']?Bearer\s+([a-zA-Z0-9_\-\.]{20,})["\']?', re.IGNORECASE),
    re.compile(r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.IGNORECASE),
    re.compile(r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE),
]

# Cookie names that often contain session tokens
HTTP_SESSION_COOKIES = ['session', 'sessionid', 'session_id', 'sid', 'phpsessid', 'jsessionid',
                        'aspsessionid', 'auth', 'authorization', 'token', 'access_token', 'jwt']


def extract_json_credentials(json_str: str, session: Session, url: str) -> bool:
    """
    Extract credentials from JSON payload.
    Returns True if credentials were found, False otherwise.
    """
    try:
        data = json.loads(json_str)

        credentials = Credentials()
        credentials.context["Method"] = "POST (JSON)"
        credentials.context["URL"] = url

        # Check if it's a dict
        if isinstance(data, dict):
            # Look for common username/password fields
            for key in data:
                key_lower = key.lower()
                if key_lower in HTTP_AUTH_POTENTIAL_USERNAMES:
                    credentials.username = str(data[key])
                elif key_lower in HTTP_AUTH_POTENTIAL_PASSWORDS:
                    credentials.password = str(data[key])

            if credentials.username or credentials.password:
                logger.found(session, f"JSON credentials found: {credentials.username} -- {credentials.password}")
                session.credentials_list.append(credentials)
                return True

    except (json.JSONDecodeError, ValueError):
        pass

    return False


def extract_api_keys(content: str, session: Session, url: str):
    """
    Extract API keys and tokens from content using regex patterns.
    """
    for pattern in HTTP_API_KEY_PATTERNS:
        matches = pattern.findall(content)
        for match in matches:
            logger.found(session, f"API key/token found: {match[:20]}... in {url}")
            credentials = Credentials()
            credentials.context["Type"] = "API Key/Token"
            credentials.context["URL"] = url
            credentials.hash = match  # Store the token in hash field
            session.credentials_list.append(credentials)


def extract_cookies(cookie_header: str, session: Session, url: str):
    """
    Extract session cookies and authentication tokens from Cookie header.
    """
    # Parse cookies: "cookie1=value1; cookie2=value2"
    cookies = cookie_header.split(';')

    for cookie in cookies:
        cookie = cookie.strip()
        if '=' in cookie:
            name, value = cookie.split('=', 1)
            name_lower = name.lower()

            # Check if this is a session/auth cookie
            if any(session_name in name_lower for session_name in HTTP_SESSION_COOKIES):
                if len(value) > 10:  # Only report substantial cookie values
                    logger.found(session, f"Session cookie '{name}' found: {value[:30]}... in {url}")
                    credentials = Credentials()
                    credentials.context["Type"] = "Session Cookie"
                    credentials.context["Cookie Name"] = name
                    credentials.context["URL"] = url
                    credentials.hash = value
                    session.credentials_list.append(credentials)


def analyse(session: Session, layer: BaseLayer):

    current_creds = session.credentials_being_built

    if hasattr(layer, "request_uri"):

        extension = layer.request_uri.split(".")[-1]

        if extension in HTTP_IGNORED_EXTENSIONS:
            return

        # Ignore Certificate Status Protocol
        if hasattr(layer, "request_full_uri") and layer.request_full_uri.startswith("http://ocsp."):
            return

        # Extract cookies from Cookie header
        if hasattr(layer, "cookie"):
            url = layer.request_full_uri if hasattr(layer, "request_full_uri") else layer.request_uri
            extract_cookies(layer.cookie, session, url)

        if hasattr(layer, "authorization"):
            tokens = layer.authorization.split(" ")

            if len(tokens) == 2 and tokens[0] == "Basic":
                try:
                    credentials = base64.b64decode(tokens[1]).decode()
                    colon_index = credentials.find(":")
                    current_creds.username = credentials[:colon_index]
                    current_creds.password = credentials[colon_index+1:]
                    session["authorization_header_uri"] = layer.request_full_uri
                except UnicodeDecodeError:
                    logger.error("HTTP Basic auth failed: " + tokens)

            elif len(tokens) == 2 and tokens[0] == "NTLM":
                pass  # Already handled by the NTLMSSP module

            else:
                logger.info(session, "Authorization header found: '{}'".format(layer.authorization))

        # POST parameters
        if hasattr(layer, "file_data"):
            post_content_hex = layer.file_data

            # Decode hex data to bytes, then to string
            try:
                post_content_bytes = bytes.fromhex(post_content_hex.replace(":", ""))
                post_content = post_content_bytes.decode('utf-8', errors='ignore')
            except (ValueError, UnicodeDecodeError) as e:
                logger.info(session, f"Failed to decode POST data: {e}")
                return

            if len(post_content) <= HTTP_AUTH_MAX_LOGIN_POST_LENGTH:
                logger.info(session, "POST data found: '{}'".format(post_content))

                url = layer.request_full_uri if hasattr(layer, "request_full_uri") else ""

                # Check if this is JSON content
                if post_content.strip().startswith('{') or post_content.strip().startswith('['):
                    if extract_json_credentials(post_content, session, url):
                        return  # JSON credentials found and extracted

                    # Also check for API keys in JSON
                    extract_api_keys(post_content, session, url)

                # Try to parse as form data
                post_parameters = parse_qs(post_content)

                # We don't want to interfere with the Authorization header potentially being built
                credentials = Credentials()

                credentials.context["Method"] = "POST"
                credentials.context["URL"] = url

                logger.info(session, "context: " + str(credentials.context))

                for parameter in post_parameters:
                    if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                        credentials.username = post_parameters[parameter][0]
                    elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                        credentials.password = post_parameters[parameter][0]

                if credentials.username:
                    logger.found(session, "credentials found: {} -- {}".format(credentials.username, credentials.password))
                    session.credentials_list.append(credentials)  # Don't validate those credentials
                    return

                # Also check for API keys in form data
                extract_api_keys(post_content, session, url)

        # GET parameters
        elif hasattr(layer, "request_uri_query"):
            get_parameters = parse_qs(layer.request_uri_query)

            # We don't want to interfere with the Authorization header potentially being built
            credentials = Credentials()

            url = layer.request_full_uri if hasattr(layer, "request_full_uri") else ""

            credentials.context["Method"] = "GET"
            credentials.context["URL"] = url

            for parameter in get_parameters:
                if parameter in HTTP_AUTH_POTENTIAL_USERNAMES:
                    credentials.username = get_parameters[parameter][0]
                elif parameter in HTTP_AUTH_POTENTIAL_PASSWORDS:
                    credentials.password = get_parameters[parameter][0]

            if credentials.username:
                logger.found(session, "credentials found: {} -- {}".format(credentials.username, credentials.password))
                logger.info(session, "context: " + str(credentials.context))
                session.credentials_list.append(credentials)  # Don't validate those credentials
                return

            # Also check for API keys in GET parameters
            extract_api_keys(layer.request_uri_query, session, url)

    elif hasattr(layer, "response_for_uri"):

        if "authorization_header_uri" in session and session["authorization_header_uri"] == layer.response_for_uri:

            # If auth failed + prevent duplicates
            if layer.response_code == "401" or current_creds in session.credentials_list:
                session.invalidate_credentials_and_clear_session()

            else:
                logger.found(session, f"basic auth credentials found: {current_creds.username} -- {current_creds.password}")
                session.validate_credentials()

        # Extract files from HTTP responses if file extraction is enabled
        file_extractor = get_file_extractor()
        if file_extractor and hasattr(layer, "file_data"):
            try:
                # Decode hex data to bytes
                file_data_hex = layer.file_data.replace(":", "")
                file_data = bytes.fromhex(file_data_hex)

                # Get MIME type from Content-Type header if available
                mime_type = None
                if hasattr(layer, "content_type"):
                    mime_type = layer.content_type

                # Get URL
                url = layer.response_for_uri if hasattr(layer, "response_for_uri") else ""

                # Extract source and destination IPs
                source_ip = ""
                dest_ip = ""
                session_str = str(session)
                # Session format: "HTTP IP1:PORT <-> IP2:PORT"
                if "<->" in session_str:
                    parts = session_str.split("<->")
                    if len(parts) == 2:
                        source_ip = parts[0].strip().split()[-1].split(':')[0]
                        dest_ip = parts[1].strip().split(':')[0]

                # Save the file
                saved_path = file_extractor.save_file(
                    data=file_data,
                    mime_type=mime_type,
                    url=url,
                    source_ip=source_ip,
                    dest_ip=dest_ip
                )

                if saved_path:
                    logger.info(session, f"File extracted: {saved_path}")

            except (ValueError, Exception) as e:
                logger.info(session, f"Failed to extract file: {e}")
