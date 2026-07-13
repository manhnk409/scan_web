import nmap
from urllib.parse import urlparse
import socket

def scan_nmap(url):

    try:

        host = urlparse(url).hostname

        ip = socket.gethostbyname(host)

        nm = nmap.PortScanner()

        nm.scan(ip, arguments="-F -sV")

        if ip not in nm.all_hosts():
            return {
                "error": "Host not found",
                "hosts_found": nm.all_hosts()
            }

        result = {}

        for proto in nm[ip].all_protocols():

            result[proto] = []

            for port in nm[ip][proto]:

                result[proto].append({
                    "port": port,
                    "state": nm[ip][proto][port]["state"],
                    "service": nm[ip][proto][port]["name"]
                })

        return result

    except Exception as e:
        return {
            "error": str(e)
        }