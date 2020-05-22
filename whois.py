import socket
import re

LOCAL_IPS = [
    ((10, 0, 0, 0), (255, 0, 0, 0)),
    ((172, 16, 0, 0, 12), (255, 240, 0, 0)),
    ((192, 168, 0, 0), (255, 255, 0, 0))
]

REGIONAL_WHOIS_REGISTRIES = ['wq.apnic.net',
                             'www.afrinic.net',
                             'apps.db.ripe.net',
                             'whois.arin.net',
                             'lacnic.net']


def is_ip_local(ip):
    if '*' in ip:
        return False
    ip_fragments = list(map(int, ip.split('.')))
    for ip_fragment, mask_fragment in list(
            filter(lambda x: ip_fragments[0] == x[0][0], LOCAL_IPS)):
        for i in range(4):
            if (ip_fragments[i] & mask_fragment[i]) != ip_fragment[i]:
                return False
        return True


def get_whois_packet(whois_server, address):
    with socket.socket() as s:
        s.settimeout(2)
        s.connect((whois_server, 43))
        s.send(address.encode('utf8') + b'\r\n')
        data = []
        buffer = b'stub'
        while buffer:
            try:
                buffer = s.recv(65535)
                data.append(buffer)
            except socket.error:
                break
        return (b''.join(data)).decode('utf8', errors='ignore')


def extract_whois_info(packet):
    netname = re.findall(r'netname:\s*(.*?)\n', packet, re.I)
    netname = netname[0] if netname else None
    origin = re.findall(r'origin\s?A?S?:\s*AS(\d*)\n', packet, re.I)
    origin = origin[0] if origin else None
    country = re.findall(r'country:\s*(.*?)\n', packet, re.I)
    country = country[0] if country and country[0] != 'EU' else None
    return netname, origin, country


def get_whois_info(ip):
    for registry in REGIONAL_WHOIS_REGISTRIES:
        netname, origin, country = extract_whois_info(get_whois_packet(registry, ip))
        if netname or origin or country:
            return netname, origin, country
    return None, None, None
