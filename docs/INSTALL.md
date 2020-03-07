# Installation guide (on Ubuntu 16.04)

- [Installation guide (on Ubuntu 16.04)](#installation-guide-on-ubuntu-1604)
  - [Step 1: Install the dependencies](#step-1-install-the-dependencies)
  - [Step 2: Open the firewall for port 443 traffic](#step-2-open-the-firewall-for-port-443-traffic)
    - [Step 2a: Create a reverse proxy (OPTIONAL)](#step-2a-create-a-reverse-proxy-optional)
    - [Step 2b: Port redirection (OPTIONAL)](#step-2b-port-redirection-optional)
  - [Step 3: Create a user account](#step-3-create-a-user-account)
  - [Step 4: Checkout the code](#step-4-checkout-the-code)
  - [Step 5: Create a self-signed certificate](#step-5-create-a-self-signed-certificate)
  - [Step 6: Setup Virtual Environment](#step-6-setup-virtual-environment)
  - [Step 7: Create a configuration file](#step-7-create-a-configuration-file)
  - [Step 8: Starting the honeypot](#step-8-starting-the-honeypot)
  - [Configure Additional Output Plugins (OPTIONAL)](#configure-additional-output-plugins-optional)
  - [Docker Usage (Optional)](#docker-usage-optional)
  - [Command-line options](#command-line-options)
  - [Upgrading the honeypot](#upgrading-the-honeypot)

## Step 1: Install the dependencies

First we install system-wide support for Python virtual environments and other
dependencies. Actual Python packages are installed later.

For a Python2-based environment:

```bash
sudo apt-get update
sudo apt-get install git python-virtualenv libffi-dev build-essential libpython-dev python2.7-minimal python-dev libmysqlclient-dev
```

## Step 2: Open the firewall for port 443 traffic

If TCP port 443 is not aleady opened for incoming connections on your firewall
and router, you must open it now.

To open it on the firewall, execute the following command:

```bash
sudo ufw allow 443/tcp
```

If your honeypot machine is behind a NAT router, you must open the router
for traffic coming over port 443 too. How exactly this is done depends on
the router model; please consult the instruction manual of the router.

### Step 2a: Create a reverse proxy (OPTIONAL)

Have in mind that if the machine you're installing the honeypot on is already
running a web server, the latter is already listening to port 443. Two programs
cannot listen to the same port, so in such a case we need a little trick.

The trick is based on the fact that the honeypot does not need to listen to
every request coming via port 443. It only needs the requests trying to fetch
the path `/vpn`. Therefore, we can configure the web server to act as a reverse
proxy and to forward to, e.g., `localhost:4443` every request that starts with
`/vpn`, and then configure the honeypot to listen to port 4443.

If your web server is Nginx, this can be done by including the following lines
in your `/etc/nginx/sites-available/default` file:

```nginx
server {
    listen 443 ssl http2;

    server_name your.server.fqdn;
    root /var/www/html;
    location /vpn {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Real-Port $server_port;
        proxy_pass https://localhost:4443;
    }
}
```

If your web server is Apache (warning: I don't have experience with it myself,
so the following information might not be entirely correct), first you need to
locate its configuration file. It most likely resides in
`/etc/apache2/apache2.conf` but if it is not, run the command

```bash
`apache2 -V | grep -F SERVER_CONFIG_FILE`
```

(On other Linux distributions, like CentOS or RedHat, you might have to use
`httpd` instead of `apache2`.)

Make sure the relevant modules are installed and enabled:

```bash
sudo apt-get install libapache2-mod-proxy-html a2enmod mod_proxy
sudo a2enmod remoteip
sudo a2enmod mod_proxy_http
```

In `apache2.conf`, define a reverse proxy:

```apache2.conf
Listen 443
<VirtualHost *:443>
    ServerName your.fqdn.name
    SSLProxyEngine on
    ProxyPreserveHost On

    <Location "/vpn">
        ProxyPass "https://localhost:4443/"
        ProxyPassReverse "https://localhost:4443/"
        RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
        RequestHeader set X-Real-Port "%{SERVER_PORT}s"
    </Location>

</VirtualHost>
```

Finally, reload the web server:

```bash
sudo service apache2 reload
```

### Step 2b: Port redirection (OPTIONAL)

If you're not using a reverse proxy and have the honeypot listen to the
Internet directly, have in mind that by default CitrixHoneypot listens on port
443 (like a real NetScaler device), although this could be modified from the
configuration file. However, most Linux distributions do not allow non-root
users to listen on ports lower than 1024 - and running the honeypot as `root`
is not advisable, for security reasons.

There are two possible approaches for solving this problem. One is to redirect
the incoming traffic from port 443 to some other port, e.g., 4443 at the
firewall and to configure the honeypot to listen to that port. This has
system-wide implications and has to be done from a user who can `sudo` (i.e,
not from the user `citrix` - but after this user has been created in
[step 3](#step-3-create-a-user-account)):

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 4443
```

Note that you should test this rule only from another host; it doesn't apply
to loopback connections.

The second way is to use authbind and allow the honeypot to listen to port 443
directly:

```bash
sudo apt-get install authbind
sudo touch /etc/authbind/byport/443
sudo chown citrix:citrix /etc/authbind/byport/443
sudo chmod 770 /etc/authbind/byport/443
```

Then edit the file `etc/honeypot-launch.cfg` and modify the
AUTHBIND_ENABLED setting after [step 7](#step-7-create-a-configuration-file).

## Step 3: Create a user account

It's strongly recommended to run the honeypot as a dedicated non-root user
(named `citrix` in our example), who cannot `sudo`:

```bash
$ sudo adduser --disabled-password citrix
Adding user 'citrix' ...
Adding new group 'citrix' (1002) ...
Adding new user 'citrix' (1002) with group 'citrix' ...
Changing the user information for citrix
Enter the new value, or press ENTER for the default
Full Name []:
Room Number []:
Work Phone []:
Home Phone []:
Other []:
Is the information correct? [Y/n]

$ sudo su - citrix
```

## Step 4: Checkout the code

```bash
$ git clone https://gitlab.com/bontchev/CitrixHoneypot.git
Cloning into 'CitrixHoneypot'...
remote: Enumerating objects: 116, done.
remote: Counting objects: 100% (116/116), done.
remote: Compressing objects: 100% (62/62), done.
remote: Total 116 (delta 56), reused 90 (delta 45), pack-reused 0
Receiving objects: 100% (116/116), 61.36 KiB | 1.75 MiB/s, done.
Resolving deltas: 100% (56/56), done.

$ cd CitrixHoneypot
```

## Step 5: Create a self-signed certificate

```bash
openssl req -newkey rsa:2048 -nodes -keyout ssl/key.pem -x509 -days 365 -out ssl/cert.pem
```

## Step 6: Setup Virtual Environment

Next you need to create your virtual environment:

```bash
$ pwd
/home/citrix/CitrixHoneypot
$ virtualenv citrix-env
New python executable in ./citrix-env/bin/python
Installing setuptools, pip, wheel...done.
```

Activate the virtual environment and install the necessary dependencies

```bash
$ source citrix-env/bin/activate
(citrix-env) $ pip install --upgrade pip
(citrix-env) $ pip install --upgrade -r requirements.txt
```

## Step 7: Create a configuration file

The configuration for the honeypot is stored in `etc/honeypot.cfg.base` and
`etc/honeypot.cfg`. Both files are read on startup but the entries from
`etc/honeypot.cfg` take precedence. The `.base` file contains the default
settings and can be overwritten by upgrades, while `honeypot.cfg` will not be
touched. To run with a standard configuration, there is no need to change
anything.

For instance, in order to enable JSON logging, create `etc/honeypot.cfg` and
put in it only the following:

```honeypot.cfg
[output_jsonlog]
enabled = true
logfile = log/citrix.json
epoch_timestamp = true
```

For more information about how to configure additional output plugins (from
the available ones), please consult the appropriate `README.md` file in the
subdirectory corresponding to the plugin inside the `docs` directory.

## Step 8: Starting the honeypot

Before starting the honeypot, make sure that you have specified correctly
where it should look for the virtual environment. This documentation suggests
that you create it in `/home/citrix/CitrixHoneypot/citrix-env/`. If you have indeed
created it there, there is no need to change anything. If, however, you have
created it elsewhere, you have to do the following:

- Make a copy of the file `honeypot-launch.cfg.base`:

```bash
$ pwd
/home/citrix/CitrixHoneypot
$ cd etc
$ cp honeypot-launch.cfg.base honeypot-launch.cfg
$ cd ..
```

- Edit the file `/home/citrix/CitrixHoneypot/etc/honeypot-launch.cfg` and change the
  setting of the variable `HONEYPOT_VIRTUAL_ENV` to point to the directory where your
  virtual environment is.

Now you can launch the honeypot:

```bash
$ pwd
/home/citrix/CitrixHoneypot
$ ./bin/honeypot start
Starting the honeypot ...
The honeypot was started successfully.
```

## Configure Additional Output Plugins (OPTIONAL)

The honeypot automatically outputs event data to text in `log/honeypot.log`.
Additional output plugins can be configured to record the data other ways.
Supported output plugins include:

- JSON
- MySQL

More plugins are likely to be added in the future.

See `docs/[Output Plugin]/README.md` for details.

## Docker Usage (Optional)

First, from a user who can `sudo` (i.e., not from the user `citrix`) make
sure that `docker` is installed and that the user `citrix` is a member of
the `docker` group:

```bash
sudo apt-get install docker.io
sudo usermod -a -G docker citrix
```

**WARNING!** The a user who belongs to the `docker` group has root user
privileges, which negates the advantages of creating the `citrix` user as a
restricted user in the first place. If a user is not a member of the `docker`
group, the only way for them to use Docker is via `sudo` - which a restricted
user like `citrix` cannot do. Since this increases the
[attack surface](https://docs.docker.com/engine/security/security/#docker-daemon-attack-surface),
we advise against using the honeypot with Docker. One alternative is to look
into other containerization systems that do not require privileged user access
in order to operate - e.g., [Podman](https://podman.io/).

Then switch to the user `citrix`, build the Docker image, and run it:

```bash
sudo su - citrix
docker build -t citrixhoneypot .
docker run -d -p 443:443/tcp -u $(id -u):$(id -g) -v $(HOME}/CitrixHoneypot:/CitrixHoneypot -w /CitrixHoneypot citrixhoneypot
```

## Command-line options

CitrixHoneypot supports the following command-line options:

```options
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -a ADDR, --addr ADDR  Address to bind to (default: 0.0.0.0)
  -p PORT, --port PORT  Port to listen on (default: 443)
  -l LOGFILE, --logfile LOGFILE
                        Log file (default: stdout)
  -d SSLDIR, --ssldir SSLDIR
                        Directory of the SSL certificate (default: ssl)
  -s SENSOR, --sensor SENSOR
                        Sensor name (default: bontchev-PC)
```

The settings specified via command-line options take precedence over the
corresponding settings in the `.cfg` files.

## Upgrading the honeypot

Updating is an easy process. First stop your honeypot. Then fetch any
available updates from the repository. As a final step upgrade your Python
dependencies and restart the honeypot:

```bash
./bin/honeypot stop
git pull
pip install --upgrade -r requirements.txt
./bin/honeypot start
```
