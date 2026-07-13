import ssl
import socket
from urllib.parse import urlparse


def scan_ssl(url, verify_ssl=True):

    try:

        host = urlparse(url).hostname

        if verify_ssl:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()

        with ctx.wrap_socket(
            socket.socket(),
            server_hostname=host
        ) as socket_connection:

            socket_connection.settimeout(5)
            socket_connection.connect((host, 443))

            cert = socket_connection.getpeercert()

            return {
                "issuer": cert.get("issuer"),
                "subject": cert.get("subject"),
                "expires": cert.get("notAfter"),
                "verification": "enabled" if verify_ssl else "disabled",
            }

    except Exception as error:
        return {
            "error": str(error)
        }
