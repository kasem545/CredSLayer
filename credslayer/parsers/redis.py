# coding: utf-8

"""
Redis protocol parser for extracting AUTH credentials.
Redis uses a simple text-based protocol (RESP - REdis Serialization Protocol).
"""

from pyshark.packet.layers.base import BaseLayer

from credslayer.core import logger
from credslayer.core.session import Session


def analyse(session: Session, layer: BaseLayer):
    """
    Analyze Redis protocol packets for authentication credentials.

    Redis AUTH command format:
    - AUTH <password>
    - AUTH <username> <password> (Redis 6+)
    """

    current_creds = session.credentials_being_built

    # Redis commands are usually in the data field
    if hasattr(layer, "data"):
        try:
            # Decode hex data to string
            data_hex = layer.data.replace(":", "")
            data_bytes = bytes.fromhex(data_hex)
            data_str = data_bytes.decode('utf-8', errors='ignore')

            # Look for AUTH command
            # Format: *2\r\n$4\r\nAUTH\r\n$<len>\r\n<password>\r\n
            # Or: *3\r\n$4\r\nAUTH\r\n$<len>\r\n<username>\r\n$<len>\r\n<password>\r\n

            lines = data_str.split('\r\n')

            for i, line in enumerate(lines):
                if line.upper() == 'AUTH':
                    # Check if we have username and password (Redis 6+)
                    # or just password (older versions)
                    remaining = [l for l in lines[i+1:] if l and not l.startswith('$') and not l.startswith('*')]

                    if len(remaining) >= 2:
                        # Redis 6+ with username
                        current_creds.username = remaining[0]
                        current_creds.password = remaining[1]
                        logger.found(session, f"Redis credentials found: {current_creds.username} -- {current_creds.password}")
                    elif len(remaining) >= 1:
                        # Older Redis with just password
                        current_creds.password = remaining[0]
                        logger.found(session, f"Redis password found: {current_creds.password}")

                    current_creds.context["Protocol"] = "Redis"
                    session.validate_credentials()
                    break

        except (ValueError, UnicodeDecodeError) as e:
            logger.info(session, f"Failed to decode Redis data: {e}")
