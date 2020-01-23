#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Licencing Agreement: MalwareTech Public Licence
This software is free to use providing the user yells "Oh no, the cyberhackers are coming!" prior to each installation.
"""

from __future__ import print_function
from future.standard_library import install_aliases
install_aliases()

import os
import sys
import ssl
import time
import errno
import socket
import logging
import traceback
import logging.handlers
from http import server
from core.config import CONFIG
from urllib.parse import urlparse
from argparse import ArgumentParser

__VERSION__ = '2.0.0'

struggle_check = False


def mkdir(path):
    if not path:
        return
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


class CitrixHandler(server.SimpleHTTPRequestHandler):
    page_cache = {'403.html': '', 'login.html': '', 'smb.conf': '', 'gold_star.html': ''}

    def __init__(self, args, directory, kwargs):
        super().__init__(args, directory, kwargs)

    def do_HEAD(self):
        path = urlparse.unquote(self.path)

        self.log(logging.INFO, 'HEAD Header: {}'.format(path))

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        if path.find('/../') != -1:
            # flatten path to ease parsing
            collapsed_path = server._url_collapse_path(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    self.log(logging.WARN, 'Detected type 1 CVE-2019-19781 scan attempt!')

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    self.log(logging.WARN, 'Detected type 2 CVE-2019-19781 scan attempt!')

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    self.log(logging.DEBUG, 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))

        self.send_response('')

    # handle GET requests and attempt to emulate a vulnerable server
    def do_GET(self):
        path = urlparse.unquote(self.path)

        self.log(logging.INFO, 'GET Header: {}'.format(path))

        if self.struggle_check(path):
            return

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        # if url is empty or path is /vpn/, display fake login page
        if len(url_path) == 0 or (len(url_path) == 1 and url_path[0] == 'vpn'):
            return self.send_response(self.get_page('login.html'))

        # only proceed if a directory traversal was attempted
        if path.find('/../') != -1:
            # flatten path to ease parsing
            collapsed_path = server._url_collapse_path(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    self.log(logging.WARN, 'Detected type 1 CVE-2019-19781 scan attempt!')
                    page_403 = self.get_page('403.html').replace('{url}', collapsed_path)
                    return self.send_response(page_403)

                if len(url_path) >= 2 and url_path[0] == 'vpns' and url_path[1] == 'portal':
                    self.log(logging.CRITICAL, 'Detected CVE-2019-19781 completion!')
                    return self.send_response('')

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    self.log(logging.WARN, 'Detected type 2 CVE-2019-19781 scan attempt!')
                    return self.send_response(self.get_page('smb.conf'))

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    self.log(logging.DEBUG, 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))
                    self.send_response('')

        # if all else fails return nothing
        return self.send_response('')

    # handle POST requests to try and capture exploit payloads
    def do_POST(self):
        path = urlparse.unquote(self.path)

        self.log(logging.INFO, 'POST Header: {}'.format(path))

        if 'Content-Length' in self.headers:
            collapsed_path = server._url_collapse_path(path)
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.log(logging.INFO, 'POST body: {}'.format(post_data))

            # RCE path is /vpns/portal/scripts/newbm.pl and payload is contained in POST data
            if content_length != 0 and collapsed_path == '/vpns/portal/scripts/newbm.pl':
                payload = urlparse.parse_qs(post_data)['title'][0]
                self.log(logging.CRITICAL, 'Detected CVE-2019-19781 payload: {}'.format(payload))

        if self.struggle_check(path):
            return

        # send empty response as we're now done
        return self.send_response('')

    def log(self, log_level, msg):
        if 'X-Real-IP' in self.headers:
            ip = self.headers['X-Real-IP']
        else:
            ip = self.client_address[0]
        logging.log(log_level, '({}:{}): {}'.format(ip, self.client_address[1], msg))

    def struggle_check(self, path):
        if struggle_check:
            # if the path does not contain /../ it's likely attacker was using a sanitized client which removed it
            if path in ['/vpns/portal/scripts/newbm.pl', '/vpns/cfg/smb.conf', '/vpns/']:
                self.log(logging.DEBUG, 'Detected a failed directory traversal attempt.')
                self.send_response(self.get_page('gold_star.html'))
                return True

        return False

    # a simple wrapper to cache files from "responses" folder
    def get_page(self, page):
        # if page is not in cache, load it from file
        if self.page_cache[page] == '':
            with open('responses/{}'.format(page), 'r') as f:
                self.page_cache[page] = f.read()

        return self.page_cache[page]

    # overload base class's send_response() to set appropriate headers and server version
    def send_response(self, page, code=200, msg='OK'):
        self.wfile.write('HTTP/1.1 {} {}\r\n'.format(code, msg).encode('utf-8'))
        self.send_header('Server', 'Apache')
        self.send_header('Content-Length', len(page))
        self.send_header('Content-type', 'text/html')
        self.send_header('Connection', 'Close')
        self.end_headers()

        if page != '':
            self.wfile.write(page.encode('utf-8'))


def main():
    global struggle_check
    cfg_options = {}
    cfg_options['addr'] = CONFIG.get('honeypot', 'out_addr', fallback='0.0.0.0')
    cfg_options['port'] = CONFIG.getint('honeypot', 'listen_port', fallback=443)
    log_name = CONFIG.get('honeypot', 'log_filename', fallback='')
    if log_name:
        logdir = CONFIG.get('honeypot', 'log_path', fallback='')
        mkdir(logdir)
        cfg_options['logfile'] = os.path.join(logdir, log_name)
    else:
        cfg_options['logfile'] = None
    cfg_options['ssldir'] = CONFIG.get('honeypot', 'ssl_dir', fallback='ssl')
    cfg_options['sensor'] = CONFIG.get('honeypot', 'sensor_name', fallback=socket.gethostname())
    cfg_options['debug'] = CONFIG.get('honeypot', 'verbosity', fallback='info')
    struggle_check = CONFIG.getboolean('honeypot', 'struggle_check', fallback=False)

    parser = ArgumentParser(prog='CitrixHoneypot', description='Citrix Honeypot')

    parser.add_argument('-v', '--version', action='version', version='%(prog)s version ' + __VERSION__)
    parser.add_argument('-a', '--addr', type=str, default=cfg_options['addr'],
                        help='Address to bind to (default: {})'.format(cfg_options['addr']))
    parser.add_argument('-p', '--port', type=int, default=cfg_options['port'],
                        help='Port to listen on (default: {})'.format(cfg_options['port']))
    parser.add_argument('-l', '--logfile', type=str, default=cfg_options['logfile'],
                        help='Log file (default: stdout)')
    parser.add_argument('-d', '--ssldir', type=str, default=cfg_options['ssldir'],
                        help='Directory of the SSL certificate (default: {})'.format(cfg_options['ssldir']))
    parser.add_argument('-s', '--sensor', type=str, default=cfg_options['sensor'],
                        help='Sensor name (default: {})'.format(cfg_options['sensor']))

    args = parser.parse_args()

    cfg_options['addr'] = args.addr
    cfg_options['port'] = args.port
    cfg_options['logfile'] = args.logfile
    cfg_options['ssldir'] = args.ssldir
    cfg_options['sensor'] = args.sensor

    logging_levels = {
        'notset': 0,
        'debug': 10,
        'info': 20,
        'warning': 30,
        'error': 40,
        'critical': 50
    }

    if cfg_options['logfile'] is not None:
        handler = logging.handlers.WatchedFileHandler(cfg_options['logfile'])
    else:
        handler = logging.StreamHandler(sys.stdout)
    out_fmt = '[%(asctime)s.%(msecs)03dZ] [%(levelname)s] %(message)s'
    dt_fmt = '%Y-%m-%d %H:%M:%S'
    logging.Formatter.converter = time.gmtime
    formatter = logging.Formatter(out_fmt, dt_fmt)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging_levels[cfg_options['debug']])
    root.addHandler(handler)

    logging.log(logging.INFO, 'Citrix CVE-2019-19781 Honeypot by MalwareTech')

    httpd = server.HTTPServer((cfg_options['addr'], cfg_options['port']), CitrixHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                    certfile='{}/cert.pem'.format(cfg_options['ssldir']),
                                    keyfile='{}/key.pem'.format(cfg_options['ssldir']),
                                    server_side=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('Shutdown requested... exiting.')
    except Exception:
        traceback.print_exc(file=sys.stdout)
    sys.exit(0)


if __name__ == '__main__':
    main()
