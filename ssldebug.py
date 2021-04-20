#!/usr/bin/env python

# Copyright 2021 Eric Gustafson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import re
import socket
import ssl


Verbose = False


class ConnectingError(Exception):
    pass


def parse_hostport(hostport: str) -> (str, int):
    hostdomain_re = r"[a-zA-Z]\w*"
    fqdn_re = r"(" + hostdomain_re + r"(\." + hostdomain_re + r")*)"
    ipaddr_re = r"(\d+\.\d+\.\d+\.\d+)"
    port_re = r":(\d+)"
    match_re = r"(" + fqdn_re + r"|" + ipaddr_re + r")" + port_re
    print(f"re: {match_re}")
    # m = re.fullmatch(r"(([a-zA-Z]\w*)|(\d+\.\d+\.\d+\.\d+)):(\d+)", hostport)
    m = re.fullmatch(match_re, hostport)
    if m is None:
        raise ConnectingError(f"hostname:port ({hostport}) - failed to parse")
    return (m[1], int(m[5]))


def report_error(ex: ConnectingError):
    print(f"-- Error:  {ex}")
    if Verbose:
        print("")
        raise ex


def load_pem(pemfile, name):
    print(f"Loading {name}:  {pemfile.name}")
    return pemfile.read()


def try_connect(host: str, port: int):
    try:
        s = socket.create_connection((host, port), 0.5)  # timeout = 0.5s
    except ConnectionRefusedError as ex:
        raise ConnectingError("Connection Refused") from ex
    except socket.gaierror as ex:
        raise ConnectingError("Problem resolving host.") from ex
    except socket.timeout as ex:
        raise ConnectingError("Connection timed out.") from ex
    except Exception as ex:
        raise ConnectingError("Unknown problem connecting to host.") from ex
    print("TCP Connection - success.")
    return s


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="verbose output",
                        action="store_true")
    parser.add_argument("--hostname", help="TLS hostname")
    parser.add_argument("--ca", type=argparse.FileType('rb'),
                        help="CA file")
    parser.add_argument("--cert", type=argparse.FileType('rb'),
                        help="Cert (chain) file")
    parser.add_argument("--key", type=argparse.FileType('rb'),
                        help="Key file")
    parser.add_argument("--alpn", help="ALPN String")

    parser.add_argument("hostport", help="Hostname:Port of SSL service")

    return parser.parse_args()


if __name__ == '__main__':
    try:
        args = parse_args()
        if args.verbose:
            Verbose = True
            print("- verbose output")

        (host, port) = parse_hostport(args.hostport)
        hostname = host
        print(f"Attempting to connect to:  {host}:{port}")

        if args.hostname:
            hostname = args.hostname
            print(f"Using hostname:  {hostname}")

        context = ssl.create_default_context()
        if args.ca:
            # ca = load_pem(args.ca, "CA")
            print(f"Loading CA:  {args.ca.name}")
            context.load_verify_locations(cafile=args.ca.name)
            args.ca.close()

        if args.key and not args.cert:
            raise ConnectingError("No Cert file specified with Key file; both or none required.")

        if args.cert:
            if not args.key:
                raise ConnectingError("No Key file specified with Cert file; both or none required.")
            print(f"Loading Cert: {args.cert.name}")
            print(f"Loading Key:  {args.key.name}")
            context.load_cert_chain(certfile=args.cert.name,
                                    keyfile=args.key.name)

        if args.alpn:
            print(f"Negotiating ALPN: ['{args.alpn}']")
            context.set_alpn_protocols([args.alpn])

        with try_connect(host, port) as sock:
            with context.wrap_socket(sock, server_hostname=hostname,
                                     do_handshake_on_connect=False) as ssock:
                print("Attempting SSL Handshake ...")
                ssock.do_handshake()
                print("TLS Handshake successful.")
                print(f"TLS Version: {ssock.version()}")
                if args.alpn:
                    alpn = ssock.selected_alpn_protocol()
                    if alpn != args.alpn:
                        raise ConnectingError("ALPN Negotiation Failed.")
                    print(f"ALPN Selected: {alpn}")
                ssock.close()

    except ConnectingError as ex:
        report_error(ex)
