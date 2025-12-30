# coding: utf-8

"""
MongoDB protocol parser for extracting authentication credentials.
MongoDB uses a binary wire protocol, but we can look for authentication attempts
in the SASL authentication mechanism.
"""

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    """
    Analyze MongoDB protocol packets for authentication credentials.

    MongoDB uses SASL for authentication (SCRAM-SHA-1, SCRAM-SHA-256).
    We look for the saslStart command and extract credentials.
    """

    current_creds = session.credentials_being_built

    # Check for MongoDB wire protocol fields
    if hasattr(layer, "data"):
        try:
            # Decode hex data to string
            data_hex = layer.data.replace(":", "")
            data_bytes = bytes.fromhex(data_hex)
            data_str = data_bytes.decode('utf-8', errors='ignore')

            # Look for SASL authentication markers
            if 'saslStart' in data_str or 'SCRAM-SHA' in data_str:
                logger.info(session, "MongoDB SASL authentication detected")

                # Look for username in the payload
                # Format often includes: n,,n=<username>,r=<nonce>
                if ',n=' in data_str:
                    parts = data_str.split(',n=')
                    if len(parts) > 1:
                        username_part = parts[1].split(',')[0]
                        if username_part and len(username_part) < 100:
                            current_creds.username = username_part
                            logger.info(session, f"MongoDB username found: {username_part}")

            # Look for authenticate command (older MongoDB versions)
            if 'authenticate' in data_str.lower():
                logger.info(session, "MongoDB authentication attempt detected")

                # Try to extract user field
                if 'user' in data_str:
                    # Simple extraction - may need refinement based on actual packets
                    user_idx = data_str.find('user')
                    if user_idx != -1:
                        # Extract the value after "user"
                        remaining = data_str[user_idx+4:user_idx+100]
                        # Clean up and extract username
                        for char in ['\x00', '\x01', '\x02', '\x03', '\x04']:
                            remaining = remaining.replace(char, ' ')
                        username = remaining.strip().split()[0] if remaining.strip() else None
                        if username and 3 < len(username) < 50:
                            current_creds.username = username
                            logger.found(session, f"MongoDB username found: {username}")

            if current_creds.username:
                current_creds.context["Protocol"] = "MongoDB"
                current_creds.context["Note"] = "Password hash not extracted (SCRAM protocol)"
                session.credentials_list.append(current_creds)

        except (ValueError, UnicodeDecodeError) as e:
            logger.info(session, f"Failed to decode MongoDB data: {e}")
