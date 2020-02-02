#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Licencing Agreement: MalwareTech Public Licence
This software is free to use providing the user yells
"Oh no, the cyberhackers are coming!" prior to each installation.
"""

import os
import sys
import time
import errno
import socket
import logging
import datetime

from core.config import CONFIG
from argparse import ArgumentParser

from twisted.web import server
from twisted.web.resource import Resource
from twisted.internet import reactor, endpoints

try:
    from urllib.parse import unquote, parse_qs, urlsplit, urlunsplit
except ImportError:
    from urlparse import unquote, parse_qs, urlsplit, urlunsplit

__VERSION__ = '2.0.0'


class Index(Resource):
    isLeaf = True
    page_cache = {'403.html': '', 'login.html': '', 'smb.conf': '', 'gold_star.html': ''}

    def __init__(self, options):
        self.cfg = options

    def render_HEAD(self, request):
        path = unquote(request.uri)
        self.log(request, logging.INFO, '{}: {}'.format(request.method, path))

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        if path.find('/../') != -1:
            # flatten path to ease parsing
            #collapsed_path = server._url_collapse_path(path)
            collapsed_path = self.resolve_url(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                unix_time = time.time()
                human_time = self.getutctime(unix_time)
                local_ip = self.getlocalip()
                event = {
                    'eventid': 'citrix.connection',
                    'timestamp': human_time,
                    'unixtime': unix_time,
                    'src_ip': request.getClientAddress().host,
                    'src_port': request.getClientAddress().port,
                    'dst_ip': local_ip,
                    'dst_port': self.cfg['port'],
                    'sensor': self.cfg['sensor'],
                    'request': 'HEAD'
                }

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    self.log(request, logging.WARN, 'Detected type 1 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 1'

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    self.log(request, logging.WARN, 'Detected type 2 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 2'

                # some scanners try to fetch services.html to detect vulnerable hosts
                # Ex: https://github.com/mekoko/CVE-2019-19781/blob/master/CVE-2019-19781.py
                elif collapsed_path == '/vpns/services.html':
                    self.log(request, logging.WARN, 'Detected type 3 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 3'

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    self.log(request, logging.DEBUG, 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))
                    event['message'] = 'Unknown scan'
                self.write_event(event)

    	return self.send_response(request)

    def render_GET(self, request):
        path = unquote(request.uri)

        self.log(request, logging.INFO, '{}: {}'.format(request.method, path))

        if self.struggle_check(request, path):
            self.send_response(request)

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        # if url is empty or path is /vpn/, display fake login page
        if len(url_path) == 0 or \
           (len(url_path) == 1 and url_path[0] == 'vpn') or \
           (len(url_path) == 2 and url_path[0] == 'vpn' and url_path[1].lower().startswith('index.htm')):
            return self.send_response(self.get_page('login.html'))

        # only proceed if a directory traversal was attempted
        if path.find('/../') != -1:
            # flatten path to ease parsing
            #collapsed_path = server._url_collapse_path(path)
            collapsed_path = self.resolve_url(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                unix_time = time.time()
                human_time = self.getutctime(unix_time)
                local_ip = self.getlocalip()
                event = {
                    'eventid': 'citrix.connection',
                    'timestamp': human_time,
                    'unixtime': unix_time,
                    'src_ip': request.getClientAddress().host,
                    'src_port': request.getClientAddress().port,
                    'dst_ip': local_ip,
                    'dst_port': self.cfg['port'],
                    'sensor': self.cfg['sensor'],
                    'request': 'GET'
                }

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    self.log(request, logging.WARN, 'Detected type 1 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 1'
                    self.write_event(event)
                    page_403 = self.get_page('403.html').replace('{url}', collapsed_path)
                    return self.send_response(request, page_403)

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    self.log(request, logging.WARN, 'Detected type 2 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 2'
                    self.write_event(event)
                    return self.send_response(request, self.get_page('smb.conf'))

                # some scanners try to fetch services.html to detect vulnerable hosts
                # Ex: https://github.com/mekoko/CVE-2019-19781/blob/master/CVE-2019-19781.py
                elif collapsed_path == '/vpns/services.html':
                    self.log(request, logging.WARN, 'Detected type 3 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 3'
                    self.write_event(event)
                    return self.send_response(request, self.get_page('smb.conf'))

                elif len(url_path) >= 2 and url_path[0] == 'vpns' and url_path[1] == 'portal':
                    self.log(request, logging.CRITICAL, 'Detected CVE-2019-19781 completion!')
                    event['message'] = 'Exploit completion'
                    self.write_event(event)
                    return self.send_response(request)

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    self.log(request, logging.DEBUG, 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))
                    event['message'] = 'Unknown scan'
                    self.write_event(event)

        # if all else fails return nothing
        return self.send_response(request)

    def render_POST(self, request):
        path = unquote(request.uri)

        self.log(request, logging.INFO, '{}: {}'.format(request.method, path))

        if request.getHeader('Content-Length'):
            #collapsed_path = server._url_collapse_path(path)
            collapsed_path = self.resolve_url(path)
            content_length = int(request.getHeader('Content-Length'))
            if content_length > 0:
                post_data = request.content.read().decode('utf-8')
                self.log(request, logging.INFO, 'POST body: {}'.format(post_data))

                unix_time = time.time()
                human_time = self.getutctime(unix_time)
                local_ip = self.getlocalip()
                event = {
                    'eventid': 'citrix.payload',
                    'timestamp': human_time,
                    'unixtime': unix_time,
                    'src_ip': request.getClientAddress().host,
                    'src_port': request.getClientAddress().port,
                    'dst_ip': local_ip,
                    'dst_port': self.cfg['port'],
                    'sensor': self.cfg['sensor'],
                    'request': 'POST',
                    'message': 'Exploit',
                    'body': post_data,
                    'url': path
                }

                # RCE path is /vpns/portal/scripts/newbm.pl and payload is contained in POST data
                if collapsed_path == ['/vpns/portal/scripts/newbm.pl', '/vpns/portal/scripts/rmbm.pl']:
                    payload = parse_qs(post_data)['title'][0]
                    self.log(request, logging.CRITICAL, 'Detected CVE-2019-19781 payload: {}'.format(payload))
                    event['payload'] = payload
                    self.write_event(event)

        self.struggle_check(request, path)

        # send empty response as we're now done
        return self.send_response(request)

    def log(self, request, log_level, msg):
        if request.getHeader('X-Real-IP'):
            ip = request.getHeader('X-Real-IP')
        else:
            ip = request.getClientAddress().host
        port = request.getClientAddress().port
        logging.log(log_level, '({}:{}): {}'.format(ip, port, msg))

    def struggle_check(self, request, path):
        if self.cfg['struggle']:
            # if the path does not contain /../ it's likely attacker was using a sanitized client which removed it
            if path in ['/vpns/portal/scripts/newbm.pl', '/vpns/cfg/smb.conf', '/vpns/']:
                self.log(request, logging.DEBUG, 'Detected a failed directory traversal attempt.')
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
    def send_response(self, request, page=''):
        request.setHeader('Server', 'Apache')
        request.setHeader('Content-Length', str(len(page)))
        request.setHeader('Content-type', 'text/html')
        request.setHeader('Connection', 'Close')
        return '{}'.format(page).encode('utf-8')

    def resolve_url(self, url):
        parts = list(urlsplit(url))
        segments = parts[2].split('/')
        segments = [segment + '/' for segment in segments[:-1]] + [segments[-1]]
        resolved = []
        for segment in segments:
            if segment in ('../', '..'):
                if resolved[1:]:
                    resolved.pop()
            elif segment not in ('./', '.'):
                resolved.append(segment)
        parts[2] = ''.join(resolved)
        return urlunsplit(parts)

    def write_event(self, event):
        output_plugins = self.cfg['output_plugins']
        for plugin in output_plugins:
            try:
                plugin.write(event)
            except Exception as e:
                logging.log(logging.ERROR, e)
                continue

    def getutctime(self, unixtime):
        return datetime.datetime.utcfromtimestamp(unixtime).isoformat() + 'Z'

    def getlocalip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip


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


def get_options(cfg_options):
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
    return args


def set_logger(cfg_options):
    logging_levels = {
        'notset': 0,
        'debug': 10,
        'info': 20,
        'warning': 30,
        'error': 40,
        'critical': 50
    }
    if cfg_options['logfile'] is None:
        handler = logging.StreamHandler(sys.stdout)
    else:
        handler = logging.handlers.WatchedFileHandler(cfg_options['logfile'])
    out_fmt = '[%(asctime)s.%(msecs)03dZ] [%(levelname)s] %(message)s'
    dt_fmt = '%Y-%m-%d %H:%M:%S'
    logging.Formatter.converter = time.gmtime
    formatter = logging.Formatter(out_fmt, dt_fmt)
    handler.setFormatter(formatter)
    loglevel = cfg_options['debug']
    if loglevel not in logging_levels:
        loglevel = 'debug'
    root = logging.getLogger()
    root.setLevel(logging_levels[loglevel])
    root.addHandler(handler)


def import_plugins(cfg):
    # Load output modules (inspired by the Cowrie honeypot)
    logging.log(logging.INFO, 'Loading plugins...')
    output_plugins = []
    general_options = cfg
    for x in CONFIG.sections():
        if not x.startswith('output_'):
            continue
        if CONFIG.getboolean(x, 'enabled') is False:
            continue
        engine = x.split('_')[1]
        try:
            output = __import__('output_plugins.{}'.format(engine),
                                globals(), locals(), ['output'], 0).Output(general_options)
            output_plugins.append(output)
            logging.log(logging.INFO, 'Loaded output engine: {}'.format(engine))
        except ImportError as e:
            logging.log(logging.ERROR, 'Failed to load output engine: {} due to ImportError: {}'.format(engine, e))
        except Exception as e:
            logging.log(logging.ERROR, 'Failed to load output engine: {} {}'.format(engine, e))
    return output_plugins


def stop_plugins(cfg):
    logging.log(logging.INFO, 'Stoping the plugins... ')
    for plugin in cfg['output_plugins']:
        try:
            plugin.stop()
        except Exception as e:
            logging.log(logging.ERROR, e)
            continue


def main():
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
    cfg_options['struggle'] = CONFIG.getboolean('honeypot', 'struggle_check', fallback=False)

    args = get_options(cfg_options)

    cfg_options['addr'] = args.addr
    cfg_options['port'] = args.port
    cfg_options['logfile'] = args.logfile
    cfg_options['ssldir'] = args.ssldir
    cfg_options['sensor'] = args.sensor

    set_logger(cfg_options)

    logging.log(logging.INFO, 'Citrix CVE-2019-19781 Honeypot by MalwareTech')

    cfg_options['output_plugins'] = import_plugins(cfg_options)

    site = server.Site(Index(cfg_options))
    endpoint_spec = 'ssl:interface={}:port={}:privateKey={}/key.pem:certKey={}/cert.pem'.format(
        cfg_options['addr'],
        cfg_options['port'],
        cfg_options['ssldir'],
        cfg_options['ssldir']
    )
    logging.log(logging.INFO, 'Listening on {}:{}.'.format(cfg_options['addr'], cfg_options['port']))
    endpoints.serverFromString(reactor, endpoint_spec).listen(site)
    reactor.run()   # pylint: disable=no-member
    logging.log(logging.INFO, 'Shutdown requested, exiting...')
    stop_plugins(cfg_options)


if __name__ == '__main__':
    main()
