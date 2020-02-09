
import time

from core import tools

from twisted.python import log
from twisted.web.resource import Resource

try:
    from urllib.parse import unquote, parse_qs
except ImportError:
    from urlparse import unquote, parse_qs


class Index(Resource):
    isLeaf = True
    page_cache = {'403.html': '', 'login.html': '', 'smb.conf': '', 'gold_star.html': ''}

    def __init__(self, options):
        self.cfg = options

    def render_HEAD(self, request):
        path = unquote(request.uri.decode('utf-8'))
        tools.logger(request, 'INFO', '{}: {}'.format(request.method, path))

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        if path.find('/../') != -1:
            # flatten path to ease parsing
            collapsed_path = tools.resolve_url(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                unix_time = time.time()
                human_time = tools.getutctime(unix_time)
                local_ip = tools.getlocalip()
                event = {
                    'eventid': 'citrix.connection',
                    'timestamp': human_time,
                    'unixtime': unix_time,
                    'src_ip': tools.get_real_ip(request),
                    'src_port': tools.get_real_port(request),
                    'dst_ip': local_ip,
                    'dst_port': self.cfg['port'],
                    'sensor': self.cfg['sensor'],
                    'request': 'HEAD',
                    'url': path
                }

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    tools.logger(request, 'WARNING', 'Detected type 1 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 1'

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    tools.logger(request, 'WARNING', 'Detected type 2 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 2'

                # some scanners try to fetch services.html to detect vulnerable hosts
                # Ex: https://github.com/mekoko/CVE-2019-19781/blob/master/CVE-2019-19781.py
                elif collapsed_path == '/vpns/services.html':
                    tools.logger(request, 'WARNING', 'Detected type 3 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 3'

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    tools.logger(request, 'DEBUG', 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))
                    event['message'] = 'Unknown scan'
                tools.write_event(event, self.cfg)

        return self.send_response(request)

    def render_GET(self, request):
        path = unquote(request.uri.decode('utf-8'))

        tools.logger(request, 'INFO', '{}: {}'.format(request.method, path))

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
            collapsed_path = tools.resolve_url(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                unix_time = time.time()
                human_time = tools.getutctime(unix_time)
                local_ip = tools.getlocalip()
                event = {
                    'eventid': 'citrix.connection',
                    'timestamp': human_time,
                    'unixtime': unix_time,
                    'src_ip': tools.get_real_ip(request),
                    'src_port': tools.get_real_port(request),
                    'dst_ip': local_ip,
                    'dst_port': self.cfg['port'],
                    'sensor': self.cfg['sensor'],
                    'request': 'GET',
                    'url': path
                }

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    tools.logger(request, 'WARNING', 'Detected type 1 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 1'
                    tools.write_event(event, self.cfg)
                    page_403 = self.get_page('403.html').replace('{url}', collapsed_path)
                    return self.send_response(request, page_403)

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    tools.logger(request, 'WARNING', 'Detected type 2 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 2'
                    tools.write_event(event, self.cfg)
                    return self.send_response(request, self.get_page('smb.conf'))

                # some scanners try to fetch services.html to detect vulnerable hosts
                # Ex: https://github.com/mekoko/CVE-2019-19781/blob/master/CVE-2019-19781.py
                elif collapsed_path == '/vpns/services.html':
                    tools.logger(request, 'WARNINg', 'Detected type 3 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 3'
                    tools.write_event(event, self.cfg)
                    return self.send_response(request, self.get_page('smb.conf'))

                elif len(url_path) >= 2 and url_path[0] == 'vpns' and url_path[1] == 'portal':
                    tools.logger(request, 'CRITICAL', 'Detected CVE-2019-19781 completion!')
                    event['message'] = 'Exploit completion'
                    tools.write_event(event, self.cfg)
                    return self.send_response(request)

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    tools.logger(request, 'DEBUG', 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))
                    event['message'] = 'Unknown scan'
                    tools.write_event(event, self.cfg)

        # if all else fails return nothing
        return self.send_response(request)

    def render_POST(self, request):
        path = unquote(request.uri.decode('utf-8'))

        tools.logger(request, 'INFO', '{}: {}'.format(request.method, path))

        if request.getHeader('Content-Length'):
            #collapsed_path = server._url_collapse_path(path)
            collapsed_path = tools.resolve_url(path)
            content_length = int(request.getHeader('Content-Length'))
            if content_length > 0:
                post_data = request.content.read().decode('utf-8')
                unix_time = time.time()
                tools.logger(request, 'INFO', 'POST body: {}'.format(post_data))
                human_time = tools.getutctime(unix_time)
                local_ip = tools.getlocalip()
                event = {
                    'eventid': 'citrix.payload',
                    'timestamp': human_time,
                    'unixtime': unix_time,
                    'src_ip': tools.get_real_ip(request),
                    'src_port': tools.get_real_port(request),
                    'dst_ip': local_ip,
                    'dst_port': self.cfg['port'],
                    'sensor': self.cfg['sensor'],
                    'request': 'POST',
                    'message': 'Exploit',
                    'body': post_data,
                    'url': path
                }

                # RCE path is /vpns/portal/scripts/newbm.pl and payload is contained in POST data
                if collapsed_path in ['/vpns/portal/scripts/newbm.pl', '/vpns/portal/scripts/rmbm.pl']:
                    payload = parse_qs(post_data)['title'][0]
                    tools.logger(request, 'CRITICAL', 'Detected CVE-2019-19781 payload: {}'.format(payload))
                    event['payload'] = payload

                tools.write_event(event, self.cfg)

        self.struggle_check(request, path)

        # send empty response as we're now done
        return self.send_response(request)

    def struggle_check(self, request, path):
        if self.cfg['struggle']:
            # if the path does not contain /../ it's likely attacker was using a sanitized client which removed it
            if path in ['/vpns/portal/scripts/newbm.pl', '/vpns/cfg/smb.conf', '/vpns/']:
                tools.logger(request, 'DEBUG', 'Detected a failed directory traversal attempt.')
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
