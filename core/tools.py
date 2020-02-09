
import os
import errno
import socket
import datetime

from core.config import CONFIG

from twisted.python import log

try:
    from urllib.parse import urlsplit, urlunsplit
except ImportError:
    from urlparse import urlsplit, urlunsplit


def get_real_ip (request):
    ip = request.getHeader('X-Real-IP')
    return request.getClientAddress().host if ip is None else ip


def get_real_port (request):
    port = request.getHeader('X-Real-Port')
    return request.getClientAddress().port if port is None else port


def getutctime(unixtime):
    return datetime.datetime.utcfromtimestamp(unixtime).isoformat() + 'Z'


def getlocalip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def resolve_url(url):
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


def logger(request, log_level, msg):
    ip = get_real_ip(request)
    port = get_real_port(request)
    log.msg('[{}] ({}:{}): {}'.format(log_level, ip, port, msg))


def write_event(event, cfg):
    output_plugins = cfg['output_plugins']
    for plugin in output_plugins:
        try:
            plugin.write(event)
        except Exception as e:
            log.err(e)
            continue


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

def import_plugins(cfg):
    # Load output modules (inspired by the Cowrie honeypot)
    log.msg('Loading the plugins...')
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
            log.msg('Loaded output engine: {}'.format(engine))
        except ImportError as e:
            log.err('Failed to load output engine: {} due to ImportError: {}'.format(engine, e))
        except Exception as e:
            log.err('Failed to load output engine: {} {}'.format(engine, e))
    return output_plugins


def stop_plugins(cfg):
    log.msg('Stoping the plugins...')
    for plugin in cfg['output_plugins']:
        try:
            plugin.stop()
        except Exception as e:
            log.err(e)
            continue

