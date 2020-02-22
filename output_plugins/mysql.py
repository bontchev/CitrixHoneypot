
import MySQLdb

import core.output

from core.config import CONFIG

from hashlib import sha256
from geoip2.database import Reader

from twisted.python import log
from twisted.enterprise.adbapi import ConnectionPool


class ReconnectingConnectionPool(ConnectionPool):
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
            return ConnectionPool._runInteraction(
                self, interaction, *args, **kw)
        except MySQLdb.OperationalError as e:   # pylint: disable=no-member
            if e[0] not in (2003, 2006, 2013):
                raise e
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return ConnectionPool._runInteraction(
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

    def local_log(self, msg):
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
            self.local_log('MySQL plugin: Error {}: {}'.format(e.args[0], e.args[1]))

        if self.geoip:
            try:
                self.reader_city = Reader(self.geoipdb_city_path)
            except:
                self.local_log('Failed to open City GeoIP database {}'.format(self.geoipdb_city_path))

            try:
                self.reader_asn = Reader(self.geoipdb_asn_path)
            except:
                self.local_log('Failed to open ASN GeoIP database {}'.format(self.geoipdb_asn_path))

    def stop(self):
        if self.geoip:
            if self.reader_city is not None:
               self.reader_city.close()
            if self.reader_asn is not None:
               self.reader_asn.close()

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
            self.dbh.runInteraction(self.connect_event, event, False)
        elif 'payload' in event['eventid']:
            self.dbh.runInteraction(self.connect_event, event, True)

    def simple_query(self, txn, sql, args):
        if self.debug:
            if len(args):
                self.local_log("output_mysql: MySQL query: {} {}".format(sql, repr(args)))
            else:
                self.local_log("output_mysql: MySQL query: {}".format(sql))
        try:
            if len(args):
                txn.execute(sql, args)
            else:
                txn.execute(sql)
            result = txn.fetchall()
        except Exception as e:
            self.local_log('output_mysql: MySQL Error: {}'.format(e))
            result = None
        return result

    def get_id(self, txn, table, column, entry):
        r = self.simple_query(txn, "SELECT `id` FROM `{}` WHERE `{}` = %s".format(table, column), (entry, ))
        if r:
            id = r[0][0]
        else:
            self.simple_query(txn, "INSERT INTO `{}` (`{}`) VALUES (%s)".format(table, column), (entry, ))
            r = self.simple_query(txn, 'SELECT LAST_INSERT_ID()', ())
            if r:
                id = int(r[0][0])
            else:
                id = 0
        return id

    def get_hashed_id(self, txn, table, entry):
        sc = entry.strip()
        shasum = sha256(sc).hexdigest()
        r = self.simple_query(txn, "SELECT `id` FROM `{}` WHERE `inputhash` = %s".format(table), (shasum, ))
        if r:
            id = int(r[0][0])
        else:
            self.simple_query(txn, "INSERT INTO `{}` (`input`, `inputhash`) VALUES (%s, %s)".format(table),
                              (sc.decode('utf-8').encode('unicode_escape'), shasum, ))
            r = self.simple_query(txn, 'SELECT LAST_INSERT_ID()', ())
            if r:
                id = int(r[0][0])
            else:
                id = 0
        return id

    def geolocate(self, remote_ip):
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
            self.local_log(e)
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
            self.local_log(e)
            org = ''
            asn_num = 0
        return country, country_code, city, org, asn_num

    def connect_event(self, txn, event, has_payload):
        remote_ip = event['src_ip']

        path_id = self.get_id(txn, 'paths', 'path', event['url'])
        message_id = self.get_id(txn, 'messages', 'message', event['message'])
        sensor_id = self.get_id(txn, 'sensors', 'name', event['sensor'])

        if has_payload:
            body_id = self.get_hashed_id(txn, 'bodies', event['body'])
            payload_id = self.get_hashed_id(txn, 'payloads', event['payload'])
            self.simple_query(txn, """
                INSERT INTO `connections` (
                    `timestamp`, `ip`, `remote_port`, `request`, `path`, `body`,
                    `payload`, `message`, `local_host`, `local_port`, `sensor`)
                VALUES (FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (event['unixtime'], remote_ip, event['src_port'], event['request'], path_id,
                body_id, payload_id, message_id, event['dst_ip'], event['dst_port'], sensor_id, ))
        else:
            self.simple_query(txn, """
                INSERT INTO `connections` (
                    `timestamp`, `ip`, `remote_port`, `request`, `path`,
                    `message`, `local_host`, `local_port`, `sensor`)
                VALUES (FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (event['unixtime'], remote_ip, event['src_port'], event['request'],
                path_id, message_id, event['dst_ip'], event['dst_port'], sensor_id, ))

        if self.geoip:
            country, country_code, city, org, asn_num = self.geolocate(remote_ip)
            self.simple_query(txn, """
                INSERT INTO `geolocation` (`ip`, `country_name`, `country_iso_code`, `city_name`, `org`, `org_asn`)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    `country_name` = %s,
                    `country_iso_code` = %s,
                    `city_name` = %s,
                    `org` = %s,
                    `org_asn` = %s
                """,
                (remote_ip, country, country_code, city, org, asn_num, country, country_code, city, org, asn_num, ))
