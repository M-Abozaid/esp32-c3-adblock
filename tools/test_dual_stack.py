"""Hardware DNS smoke/regression checks; standard library only, no router changes."""
import argparse
import concurrent.futures
import ipaddress
import secrets
import socket
import struct
import time


def query(server, name, qtype, *, edns=False, malformed=False):
    family = socket.AF_INET6 if ':' in server else socket.AF_INET
    target = socket.getaddrinfo(server, 53, family, socket.SOCK_DGRAM)[0][4]
    txid = secrets.randbelow(65536)
    question = b''.join(bytes([len(x)]) + x.encode('ascii') for x in name.split('.'))
    packet = struct.pack('!6H', txid, 0x100, 1, 0, 0, int(edns))
    packet += question + b'\0' + struct.pack('!HH', qtype, 1)
    if edns:
        packet += b'\0' + struct.pack('!HHIH', 41, 1232, 0, 0)
    if malformed:
        packet = packet[:14]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.3 if malformed else 5)
        started = time.monotonic()
        sock.sendto(packet, target)
        try:
            response, source = sock.recvfrom(4096)
        except socket.timeout:
            if malformed:
                return None
            raise
        assert not malformed, 'Malformed query unexpectedly answered'
        assert ipaddress.ip_address(source[0].split('%')[0]) == ipaddress.ip_address(server.split('%')[0])
        assert source[1] == 53
        assert len(response) >= 12
        ident, flags, qd, an, ns, ar = struct.unpack('!6H', response[:12])
        assert ident == txid and flags & 0x8000 and qd == 1
        assert flags & 15 == 0, f'DNS rcode {flags & 15}'
        return response, an, (time.monotonic() - started) * 1000


def check(server, name, qtype, blocked=False, edns=False):
    response, answers, ms = query(server, name, qtype, edns=edns)
    if blocked:
        if qtype == 1:
            assert answers == 1 and response[-4:] == bytes(4), 'A query not blocked'
        else:
            assert answers == 0, 'Blocked non-A query was forwarded'
        if edns:
            assert struct.unpack('!H', response[10:12])[0] == 0, 'Stale EDNS count'
    else:
        assert answers > 0, 'Allowed query did not resolve'
    return ms


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipv4', required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--blocked', default='doubleclick.net')
    parser.add_argument('--burst', type=int, default=40)
    args = parser.parse_args()
    for server in (args.ipv4, args.ipv6):
        for name, qt, blocked in [('example.org', 1, False), ('example.org', 28, False),
                                  (args.blocked, 1, True), (args.blocked, 28, True)]:
            ms = check(server, name, qt, blocked)
            print(f'PASS {server} {name} type={qt} {ms:.1f} ms')
        check(server, args.blocked, 1, True, edns=True)
        check(server, args.blocked, 28, True, edns=True)
        query(server, args.blocked, 1, malformed=True)
        check(server, args.blocked, 1, True)
        print(f'PASS {server} EDNS and malformed-packet recovery')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(check, (args.ipv4, args.ipv6)[i % 2], args.blocked,
                            (1, 28)[i % 2], True) for i in range(args.burst)]
        times = [job.result() for job in jobs]
    print(f'PASS {len(times)} alternating concurrent queries; max {max(times):.1f} ms')


if __name__ == '__main__':
    main()
