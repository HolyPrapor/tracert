import socket
import re

LOCAL_IPS = [
    ((10, 0, 0, 0), (255, 0, 0, 0)),
    ((172, 16, 0, 0, 12), (255, 240, 0, 0)),
    ((192, 168, 0, 0), (255, 255, 0, 0))
]


def is_ip_local(ip):
    ip_fragments = list(map(int, ip.split('.')))
    for ip_fragment, mask_fragment in list(filter(lambda x: ip_fragments[0] == x[0][0], LOCAL_IPS)):
        for i in range(4):
            if (ip_fragments[i] & mask_fragment[i]) != ip_fragment[i]:
                return False
        return True


def get_packet(whois_server, address):
    ip = address.encode('utf8') if isinstance(address, str) else address
    with socket.socket() as s:
        s.settimeout(2)
        s.connect((whois_server, 43))
        s.send(ip)
        data = []
        buffer = b'1'
        while buffer:
            try:
                buffer = s.recv(65535)
                data.append(buffer)
            except socket.error:
                break
        return b''.join(data).decode('utf8', errors='ignore')


def extract_whois_info(data):
    netname = re.findall(r'netname:\s*(.*?)\n', data, re.I)
    netname = netname[0] if netname else None
    origin = re.findall(r'origin\s?A?S?:\s*AS(\d*)\n', data, re.I)
    origin = origin[0] if origin else None
    country = re.findall(r'country:\s*(.*?)\n', data, re.I)
    country = country[0] if country and country[0] != 'EU' else None
    return netname, origin, country


def choose_whois_server(ip):
    data = get_packet('get_whois_info.iana.org', ip)
    whois = re.search(r'whois:\s*(.*)\n', data)
    if whois:
        whois = whois.group(1)
        return whois


def get_whois_info(ip):
    server = choose_whois_server(ip)
    if server:
        return extract_whois_info(get_packet(server, ip))
    return None, None, None
