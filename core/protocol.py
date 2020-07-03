
from time import time

from core import tools

from twisted.python import log
from twisted.web.resource import Resource

try:
    from urllib.parse import unquote, parse_qs
except ImportError:
    from urlparse import unquote, parse_qs


class Index(Resource):
    isLeaf = True
    page_cache = {
        '403.html': '',
        'login.html': '',
        'smb.conf': '',
        'gold_star.html': ''
    }

    def __init__(self, options):
        self.cfg = options

    def render_HEAD(self, request):
        path = unquote(request.uri.decode('utf-8'))
        method = request.method.decode('utf-8')

        tools.logger(request, 'INFO', '{}: {}'.format(method, path))

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        if path.find('/../') != -1:
            # flatten path to ease parsing
            collapsed_path = tools.resolve_url(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                unix_time = time()
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
                    'request': method,
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
        method = request.method.decode('utf-8')

        tools.logger(request, 'INFO', '{}: {}'.format(method, path))

        if self.struggle_check(request, path):
            self.send_response(request)

        # split the path by '/', ignoring empty string
        url_path = list(filter(None, path.split('/')))

        # if url is empty or path is /vpn/, display fake login page
        if len(url_path) == 0 or \
           (len(url_path) == 1 and url_path[0] == 'vpn') or \
           (len(url_path) == 2 and url_path[0] == 'vpn' and url_path[1].lower().startswith('index.htm')):
            return self.send_response(request, self.get_page('login.html'))

        # only proceed if a directory traversal was attempted
        if path.find('/../') != -1:
            # flatten path to ease parsing
            collapsed_path = tools.resolve_url(path)
            url_path = list(filter(None, collapsed_path.split('/')))

            # check if the directory traversal bug has been tried
            if len(url_path) >= 1 and url_path[0] == 'vpns':

                unix_time = time()
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
                    'request': method,
                    'url': path
                }

                # 403 on /vpn/../vpns/ is used by some scanners to detect vulnerable hosts
                # Ex: https://github.com/cisagov/check-cve-2019-19781/blob/develop/src/check_cve/check.py
                if len(url_path) == 1 and url_path[0] == 'vpns':
                    tools.logger(request, 'WARNING', 'Detected type 1 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 1'
                    response = self.get_page('403.html').replace('{url}', collapsed_path)

                # some scanners try to fetch smb.conf to detect vulnerable hosts
                # Ex: https://github.com/trustedsec/cve-2019-19781/blob/master/cve-2019-19781_scanner.py
                elif collapsed_path == '/vpns/cfg/smb.conf':
                    tools.logger(request, 'WARNING', 'Detected type 2 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 2'
                    response = self.get_page('smb.conf')

                # some scanners try to fetch services.html to detect vulnerable hosts
                # Ex: https://github.com/mekoko/CVE-2019-19781/blob/master/CVE-2019-19781.py
                elif collapsed_path == '/vpns/services.html':
                    tools.logger(request, 'WARNINg', 'Detected type 3 CVE-2019-19781 scan attempt!')
                    event['message'] = 'Scan type 3'
                    response = self.get_page('smb.conf')

                elif len(url_path) >= 2 and url_path[0] == 'vpns' and url_path[1] == 'portal':
                    tools.logger(request, 'CRITICAL', 'Detected CVE-2019-19781 completion!')
                    event['message'] = 'Exploit completion'
                    response = ''

                # we got a request that sort of matches CVE-2019-19781, but it's not a known scan attempt
                else:
                    tools.logger(request, 'DEBUG', 'Error: unhandled CVE-2019-19781 scan attempt: {}'.format(path))
                    event['message'] = 'Unknown scan'
                    response = ''
                tools.write_event(event, self.cfg)
                return self.send_response(request, response)

        # if all else fails return nothing
        return self.send_response(request)

    def render_POST(self, request):
        path = unquote(request.uri.decode('utf-8'))

        tools.logger(request, 'INFO', '{}: {}'.format(request.method.decode('utf-8'), path))

        if request.getHeader('Content-Length'):
            collapsed_path = tools.resolve_url(path)
            content_length = int(request.getHeader('Content-Length'))
            if content_length > 0:
                post_data = request.content.read().decode('utf-8')
                unix_time = time()
                tools.logger(request, 'INFO', 'POST body: {}'.format(post_data))
                human_time = tools.getutctime(unix_time)
                local_ip = tools.getlocalip()
                payload = parse_qs(post_data)['title'][0]
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
                    'payload': payload,
                    'url': path
                }

                # RCE path is /vpns/portal/scripts/newbm.pl and payload is contained in POST data
                if collapsed_path in ['/vpns/portal/scripts/newbm.pl', '/vpns/portal/scripts/rmbm.pl']:
                    tools.logger(request, 'CRITICAL', 'Detected CVE-2019-19781 payload: {}'.format(payload))

                tools.write_event(event, self.cfg)

        self.struggle_check(request, path)

        # send empty response as we're now done
        return self.send_response(request)

    def render(self, request):
        return self.render_GET(request)

    def struggle_check(self, request, path):
        if self.cfg['struggle']:
            # if the path does not contain /../ it's likely attacker was using a sanitized client which removed it
            if path in ['/vpns/portal/scripts/newbm.pl', '/vpns/cfg/smb.conf', '/vpns/']:
                tools.logger(request, 'DEBUG', 'Detected a failed directory traversal attempt.')
                self.send_response(request, self.get_page('gold_star.html'))
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
        request.setHeader('Set-Cookie', 'NSC_AAAC=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_EPAC=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_USER=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_BASEURL=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'CsrfToken=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'CtxsAuthId=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'ASP.NET_SessionId=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_TMAA=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT')
        request.setHeader('Set-Cookie', 'NSC_TMAS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure')
        request.setHeader('Set-Cookie', 'NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT')
        request.setHeader('Set-Cookie', 'NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT')
        request.setHeader('Connection', 'Close')
        request.setHeader('Content-Length', str(len(page)))
        request.setHeader('Cache-control', 'no-cache, no-store')
        request.setHeader('Pragma', 'no-cache')
        request.setHeader('Content-type', 'text/html')
        return '{}'.format(page).encode('utf-8')
