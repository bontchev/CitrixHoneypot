
import time
import MySQLdb
import hashlib
import requests
import geoip2.database

import core.output

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

from core.config import CONFIG


class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """
    Reconnecting adbapi connection pool for MySQL.
    This class improves on the solution posted at
    http://www.gelens.org/2008/09/12/reinitializing-twisted-connectionpool/
    by checking exceptions by error code and only disconnecting the current
    connection instead of all of them.
    Also see:
    http://twistedmatrix.com/pipermail/twisted-python/2009-July/020007.html
    """

    def _runInteraction(self, interaction, *args, **kw):
        try:
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)
        except MySQLdb.OperationalError as e:   # pylint: disable=no-member
            if e[0] not in (2003, 2006, 2013):
                raise e
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)


class Output(core.output.Output):

    def __init__(self, general_options):

        self.host = CONFIG.get('output_mysql', 'host', fallback='localhost')
        self.database = CONFIG.get('output_mysql', 'database', fallback='')
        self.user = CONFIG.get('output_mysql', 'username', fallback='')
        self.password = CONFIG.get('output_mysql', 'password', fallback='', raw=True)
        self.port = CONFIG.getint('output_mysql', 'port', fallback=3306)

        self.geoipdb_city_path = CONFIG.get('output_mysql', 'geoip_citydb', fallback='')
        self.geoipdb_asn_path = CONFIG.get('output_mysql', 'geoip_asndb', fallback='')

        self.debug = CONFIG.getboolean('output_mysql', 'debug', fallback=False)
        self.geoip = CONFIG.getboolean('output_mysql', 'geoip', fallback=True)

        self.dbh = None

        core.output.Output.__init__(self, general_options)

    def _local_log(self, msg):
        if self.debug:
            log.msg(msg)

    def start(self):

        try:
            self.dbh = ReconnectingConnectionPool(
                'MySQLdb',
                host=self.host,
                db=self.database,
                user=self.user,
                passwd=self.password,
                port=self.port,
                charset='utf8',
                use_unicode=True,
                cp_min=1,
                cp_max=1
            )
        except MySQLdb.Error as e:  # pylint: disable=no-member
            self._local_log('MySQL plugin: Error {}: {}'.format(e.args[0], e.args[1]))

        if self.geoip:
            try:
                self.reader_city = geoip2.database.Reader(self.geoipdb_city_path)
            except:
                self._local_log('Failed to open GeoIP database {}'.format(self.geoipdb_city_path))

            try:
                self.reader_asn = geoip2.database.Reader(self.geoipdb_asn_path)
            except:
                self._local_log('Failed to open GeoIP database {}'.format(self.geoipdb_asn_path))

    def stop(self):
        self.dbh.close()
        self.dbh = None
        if self.geoip:
            if self.reader_city is not None:
               self.reader_city.close()
            if self.reader_asn is not None:
               self.reader_asn.close()

    @defer.inlineCallbacks
    def write(self, event):
        """
        TODO: Check if the type (date, datetime or timestamp) of columns is appropriate for your needs and timezone
        - MySQL Documentation - The DATE, DATETIME, and TIMESTAMP Types
            (https://dev.mysql.com/doc/refman/5.7/en/datetime.html):
        "MySQL converts TIMESTAMP values from the current time zone to UTC for storage,
        and back from UTC to the current time zone for retrieval.
        (This does not occur for other types such as DATETIME.)"
        """
        if 'connection' in event['eventid']:
            self._connect_event(event, False)

        if 'payload' in event['eventid']:
            self._connect_event(event, True)

    @defer.inlineCallbacks
    def _get_id(self, table, column, entry):
        try:
            r = yield self.dbh.runQuery("SELECT id, {} FROM {} WHERE name='{}'".format(column, table, entry))
            if r:
                id = r[0][0]
            else:
                yield self.dbh.runQuery("INSERT INTO {} ({}) VALUES ('{}')".format(table, column, entry))
                r = yield self.dbh.runQuery('SELECT LAST_INSERT_ID()')
                id = int(r[0][0])
        except Exception as e:
            self._local_log(e)
            id = None
        return id

    @defer.inlineCallbacks
    def _get_hashed_id(self, table, entry):
        sc = entry.strip()
        shasum = hashlib.sha256(sc).hexdigest()
        r = yield self.dbh.runQuery("SELECT id FROM {} WHERE inputhash='{}'".format(table, shasum))
        if r:
            id = int(r[0][0])
        else:
            try:
                self.dbh.runQuery("INSERT INTO {} (input, inputhash) VALUES ({}, {})".format(
                                  table, sc.decode('utf-8').encode('unicode_escape'), shasum))
                r = yield self.dbh.runQuery('SELECT LAST_INSERT_ID()')
                id = int(r[0][0])
            except Exception as e:
                self._local_log(e)
                id = 0
        return id

    @defer.inlineCallbacks
    def _connect_event(self, event, has_payload):
        remote_ip = event['src_ip']
        if self.geoip:
            try:
                response_city = self.reader_city.city(remote_ip)
                city = response_city.city.name
                if city is None:
                    city = ''
                country = response_city.country.name
                if country is None:
                    country = ''
                    country_code = ''
                else:
                    country_code = response_city.country.iso_code
            except Exception as e:
                self._local_log(e)
                city = ''
                country = ''
                country_code = ''

            try:
                response_asn = self.reader_asn.asn(remote_ip)
                if response_asn.autonomous_system_organization is not None:
                    org = response_asn.autonomous_system_organization.encode('utf8')
                else:
                    org = ''

                if response_asn.autonomous_system_number is not None:
                    asn_num = response_asn.autonomous_system_number
                else:
                    asn_num = 0
            except Exception as e:
                self._local_log(e)
                org = ''
                asn_num = 0
        else:
            city = ''
            country = ''
            country_code = ''
            org = ''
            asn_num = 0

        path_id = self._get_id('paths', 'path', event['url'])
        if has_payload:
            body_id = self._get_hashed_id('bodies', event['body'])
            payload_id = self._get_hashed_id('payloads', event['payload'])
        else:
            body_id = None	# 'NULL'?
            payload_id = None	# 'NULL'?
        message_id = self._get_id('messages', 'message', event['message'])
        sensor_id = self._get_id('sensors', 'name', event['sensor'])

        try:
            yield self.dbh.runQuery("""
                INSERT INTO connections (
                    timestamp, ip, local_port, request, path, body,
                    payload, message, local_host, remote_port, sensor)
                VALUES (FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s, %s, %s. %s, %s)
                """,
                (event['unixtime'], remote_ip, event['dst_port'], event['request'], path_id,
                 body_id, payload_id, message_id, event['dst_ip'], event['src_port'], sensor_id))

            yield self.dbh.runQuery("""
                INSERT INTO geolocation (ip, country_name, country_iso_code, city_name, org, org_asn)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    country_name = '%s',
                    country_iso_code = '%s',
                    city_name = '%s',
                    org = '%s',
                    org_asn = '%s'
                """,
                (remote_ip, country, country_code, city, org, asn_num, country, country_code, city, org, asn_num))

        except Exception as e:
            self._local_log(e)

