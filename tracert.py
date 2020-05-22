import sys
import os
import socket
import argparse
import icmp
import whois


def is_root_user():
    if os.name == 'nt':
        try:
            with open("C:\\Windows\\system.ini", 'r+'):
                pass
        except OSError:
            return False
        return True
    return 'SUDO_USER' in os.environ and os.geteuid() == 0


def check_correct_ip(ip):
    splitted = ip.split('.')
    if len(splitted) != 4:
        return False
    for a in splitted:
        try:
            if int(a) > 255 or int(a) < 0:
                return False
        except:
            return False
    return True


def parse_args(args):
    parser = argparse.ArgumentParser(description="Simple TraceRoute with additional"
                                                 " information from WhoIs service.")
    parser.add_argument('destination_ip', action='store')
    parser.add_argument('depth', action='store', type=int, nargs='?',
                        default=15, help='Max TTL')

    parsed = parser.parse_args(args)

    if parsed.depth < 1:
        print("Depth is incorrect!")
        exit(2)

    return parser.parse_args(args)


def main(args):
    interface_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    if not interface_ips:
        print("No available IP interface was found!")
        exit(3)
    args = parse_args(args[1:])
    if not is_root_user():
        print("You should be under root to perform this operation!")
        exit(4)

    try:
        args.destination_ip = socket.gethostbyname(args.destination_ip)
    except socket.error:
        print(f"Address {args.destination_ip} is incorrect!")
        exit(5)

    for counter, address in enumerate(icmp.get_trace(interface_ips[0],
                                                     args.destination_ip,
                                                     args.depth, 2)):
        print(f"{counter + 1}. {address}\r\n", end='')
        if address != '*':
            if whois.is_ip_local(address):
                print('Local', end='')
            else:
                print(', '.join(filter(lambda x: x,
                                       whois.get_whois_info(address))), end='')
            print('\r\n', end='')
        print('\r\n')


if __name__ == "__main__":
    main(sys.argv)
