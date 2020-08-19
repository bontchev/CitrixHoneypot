#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Licencing Agreement: MalwareTech Public Licence
This software is free to use providing the user yells
"Oh no, the cyberhackers are coming!" prior to each installation.
"""

from os.path import join
from socket import gethostname
from argparse import ArgumentParser

from core.config import CONFIG
from core.protocol import Index
from core.logfile import set_logger
from core.tools import mkdir, import_plugins, stop_plugins

from twisted.web import server
from twisted.python import log
from twisted.internet import reactor, endpoints


__VERSION__ = '2.0.3'
__description__ = 'Citrix CVE-2019-19781 Honeypot by MalwareTech'


def get_options(cfg_options):
    parser = ArgumentParser(description=__description__)

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


def mySiteLog(request):
    """
    Empty log formatter to suppress the normal logging of
    the web requests, since we'll be doing our own logging.
    """
    return


def main():
    cfg_options = {}
    cfg_options['addr'] = CONFIG.get('honeypot', 'out_addr', fallback='0.0.0.0')
    cfg_options['port'] = CONFIG.getint('honeypot', 'listen_port', fallback=443)
    log_name = CONFIG.get('honeypot', 'log_filename', fallback='')
    if log_name:
        logdir = CONFIG.get('honeypot', 'log_path', fallback='')
        mkdir(logdir)
        cfg_options['logfile'] = join(logdir, log_name)
    else:
        cfg_options['logfile'] = None
    cfg_options['ssldir'] = CONFIG.get('honeypot', 'ssl_dir', fallback='ssl')
    cfg_options['sensor'] = CONFIG.get('honeypot', 'sensor_name', fallback=gethostname())
    cfg_options['debug'] = CONFIG.get('honeypot', 'verbosity', fallback='info')
    cfg_options['struggle'] = CONFIG.getboolean('honeypot', 'struggle_check', fallback=False)

    args = get_options(cfg_options)

    cfg_options['addr'] = args.addr
    cfg_options['port'] = args.port
    cfg_options['logfile'] = args.logfile
    cfg_options['ssldir'] = args.ssldir
    cfg_options['sensor'] = args.sensor

    set_logger(cfg_options)

    log.msg(__description__)

    cfg_options['output_plugins'] = import_plugins(cfg_options)

    site = server.Site(Index(cfg_options))
    site.log = mySiteLog
    endpoint_spec = 'ssl:interface={}:port={}:privateKey={}/key.pem:certKey={}/cert.pem'.format(
        cfg_options['addr'],
        cfg_options['port'],
        cfg_options['ssldir'],
        cfg_options['ssldir']
    )
    log.msg('Listening on {}:{}.'.format(cfg_options['addr'], cfg_options['port']))
    endpoints.serverFromString(reactor, endpoint_spec).listen(site)
    reactor.run()   # pylint: disable=no-member
    log.msg('Shutdown requested, exiting...')
    stop_plugins(cfg_options)


if __name__ == '__main__':
    main()
