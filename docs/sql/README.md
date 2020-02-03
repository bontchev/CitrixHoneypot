# Sending the Output of CitrixHoneypot to a MySQL Database

## Prerequisites

* Working CitrixHoneypot installation
* MySQL Server installation

## Installation

When writing to a MySQL database, the honeypot uses the free databases
provided by MaxMind for the purposes of geoloacting the IP addresses.
Start by installing the library necessary to work with these databases
from an account that can sudo (i.e., not from `citrix`):

```bash
sudo add-apt-repository ppa:maxmind/ppa
sudo apt-get update
sudo apt-get install python-mysqldb libmysqlclient-dev geoipupdate
```

Now switch to the `citrix` user:

```bash
sudo su - citrix
cd CitrixHoneypot
```

Go to the directory `data`, where the gelolocation databases will reside:

```bash
cd data
```

Create in this directory a file named `geoip.cfg` with the following contents:

```geoip.cfg
AccountID <ACCOUNT>
LicenseKey <KEY>
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /home/citrix/CitrixHoneypot/data
LockFile /home/citrix/CitrixHoneypot/data/.geoipupdate.lock
```

Change the paths in the options `DatabaseDirectory` and `LockFile` if you
have opted to use paths different from the ones suggested by the
CitrixHoneypot installation documentation. Make sure you replace `<ACCOUNT>`
and `<KEY>` with the account and API key obtained from MaxMind.

Download the latest version of the Maxmind geolocation databases:

```bash
geoipupdate -f geoip.cfg
```

To have the database updated automatically (it is updated every second Tuesday
of each month, so download it every second Wednesday), create a crontab job
(`crontab -e`) and enter the following:

```crontab
# Update the geoIP database at midnight on the 2nd Wednesday of each month:
0 0 8-14 * * [ $(/bin/date +\%u) -eq 3 ] && /usr/bin/geoipupdate -f /home/citrix/CitrixHoneypot/data/geoip.cfg
```

Alternatively, if you already have the MaxMind geolocation databases installed
and updated on your machine in some other place, use their respective paths in
the `[mysql_output]` section of the file `citrixhoneyot.cfg`, as mentioned
below.

## MySQL Configuration

First create a database named `citrix` and grant access to it to a user with
the same name:

```bash
$ mysql -p -u root
MySQL> CREATE DATABASE IF NOT EXISTS citrix;
MySQL> CREATE USER IF NOT EXISTS 'citrix'@'localhost' IDENTIFIED BY 'PASSWORD HERE' PASSWORD EXPIRE NEVER;
MySQL> GRANT ALTER, ALTER ROUTINE, CREATE, CREATE ROUTINE, CREATE TEMPORARY TABLES, CREATE VIEW, DELETE, DROP, EXECUTE,FILE, INDEX, INSERT, LOCK TABLES, RELOAD, SELECT, SHOW DATABASES, SHOW VIEW, TRIGGER, UPDATE ON citrix TO 'citrix'@'localhost';
MySQL> FLUSH PRIVILEGES;
MySQL> exit
```

(Make sure you specify a proper password that you want to use for the user
`citrix` instead of 'PASSWORD HERE'.)

Next, load the database schema:

```bash
$ cd /home/citrix/CitrixHoneypot/
$ mysql -p -u citrix citrix
MySQL> source ./docs/sql/mysql.sql;
MySQL> exit
```

## CitrixHoneypot Configuration

Add the following entries to `~/citrix/CitrixHoneypot/citrixhoneypot.cfg`

```citrixhoneypot.cfg
[output_mysql]
enabled = true
host = localhost
database = citrix
username = citrix
password = PASSWORD HERE
port = 3306
# Whether to store geolocation data in the database
geoip = true
# Location of the databases used for geolocation
geoip_citydb = data/GeoLite2-City.mmdb
geoip_asndb = data/GeoLite2-ASN.mmdb
# Whether to store virustotal data in the database
virustotal = true
virustotal_api_key = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Make sure you use the password you specified for the MySQL user `citrix`
instead of 'PASSWORD HERE'. Make sure the options `geoip_citydb` and
`geoip_asndb` point to the correct paths of the two MaxMind geolocation
databases. Finally, make sure that the option `virustotal_api_key` contains
a valid VirusTotal API key (obtained for free when registering a VirusTotal
account). If you do not want to have the uploaded malware scanned by
VirusTotal (and the results recorded in your MySQL database), set the option
`virustotal` to `false`.

## Restart CitrixHoneypot

```bash
cd ~/CitrixHoneypot/bin/
./citrixhoneypot restart
```

## Verify That the MySQL Output Engine Has Been Loaded

Check the end of the `~/CitrixHoneypot/log/citrix.log` to make sure that the
MySQL output plugin has been loaded successfully:

```bash
cd ~/CitrixHoneypot/log/
tail citrix.log
```

Example expected output:

```citrix.log
Listening on 0.0.0.0:4443.
Loading the plugins...
Loaded output engine: jsonlog
Loaded output engine: mysql
```

## Confirm That Events are Logged to the MySQL Database

Wait patiently for a new login attempt to occur.  Use `tail` like before to quickly check if any activity has
been recorded in the `citrix.log` file.

Once a connection event has occurred, log back into the MySQL database and verify that the event was recorded:

```bash
$ mysql -p -u citrix citrix
MySQL> SELECT * FROM connections;
```

Example output:

```mysql
+----+--------------+---------------------+---------------------+--------+-----------------+------------+----------------+-----------+-----------------------------------+------------------+---------+-------------+-------------+
| id | session      | starttime           | endtime             | sensor | ip              | local_port | country_name   | city_name | org                               | country_iso_code | org_asn | local_host  | remote_port |
+----+--------------+---------------------+---------------------+--------+-----------------+------------+----------------+-----------+-----------------------------------+------------------+---------+-------------+-------------+
|  1 | 551c6b126e4b | 2018-12-14 14:38:19 | 2018-12-14 14:38:27 |      1 | ***.***.***.*** |       5555 | Russia         |           | NForce Entertainment B.V.         | RU               |   43350 | 192.168.0.6 |       51641 |
|  2 | 1306df2cb575 | 2018-12-14 15:15:53 | 2018-12-14 15:15:53 |      1 | ***.***.***.*** |       5555 | United Kingdom | Eastleigh | British Telecommunications PLC    | GB               |    6871 | 192.168.0.6 |       53505 |
|  3 | 7071f150aa27 | 2018-12-14 16:07:25 | 2018-12-14 16:07:48 |      1 | ***.***.***.*** |       5555 | Vietnam        |           | VNPT Corp                         | VN               |   45899 | 192.168.0.6 |       40482 |
...
```
