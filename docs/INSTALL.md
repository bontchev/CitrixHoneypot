# Installation guide (on Ubuntu 16.04)

- [Installation guide (on Ubuntu 16.04)](#installation-guide-on-ubuntu-1604)
  - [Step 1: Install the dependencies](#step-1-install-the-dependencies)
  - [Step 2: Open the firewall for port 443 traffic](#step-2-open-the-firewall-for-port-443-traffic)
  - [Step 3: Create a user account](#step-3-create-a-user-account)
  - [Step 4: Checkout the code](#step-4-checkout-the-code)
  - [Step 5: Setup Virtual Environment](#step-5-setup-virtual-environment)
  - [Step 6: Create a configuration file](#step-6-create-a-configuration-file)
  - [Step 7: Starting CitrixHoneypot](#step-7-starting-citrixhoneypot)
  - [Configure Additional Output Plugins (OPTIONAL)](#configure-additional-output-plugins-optional)
  - [Command-line options](#command-line-options)
  - [Upgrading CitrixHoneypot](#upgrading-citrixhoneypot)

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
        proxy_set_header X-Real-Port $remote_port;
        proxy_pass https://localhost:4443;
    }
}
```

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
remote: Enumerating objects: 58, done.
remote: Counting objects: 100% (58/58), done.
remote: Compressing objects: 100% (40/40), done.
Uremote: Total 58 (delta 19), reused 47 (delta 13)npacking objects:  27% (16/58)
Unpacking objects: 100% (58/58), done.

$ cd CitrixHoneypot
```

## Step 5: Setup Virtual Environment

Next you need to create your virtual environment:

```bash
$ pwd
/home/citrix/citrixHoneypot
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

## Step 6: Create a configuration file

The configuration for the honeypot is stored in `etc/citrixhoneypot.cfg.base` and
`etc/citrixhoneypot.cfg`. Both files are read on startup but the entries from
`etc/citrixhoneypot.cfg` take precedence. The `.base` file contains the default
settings and can be overwritten by upgrades, while `citrixhoneypot.cfg` will not be
touched. To run with a standard configuration, there is no need to change
anything.

For instance, in order to enable JSON logging, create `etc/adbhoney.cfg` and
put in it only the following:

```citrixhoneypot.cfg
[output_jsonlog]
enabled = true
logfile = log/citrix.json
epoch_timestamp = true
```

For more information about how to configure additional output plugins (from
the available ones), please consult the appropriate `README.md` file in the
subdirectory corresponding to the plugin inside the `docs` directory.

## Step 7: Starting CitrixHoneypot

Before starting the honeypot, make sure that you have specified correctly
where it should look for the virtual environment. This documentation suggests
that you create it in `/home/citrix/CitrixHoneypot/citrix-env/`. If you have indeed
created it there, there is no need to change anything. If, however, you have
created it elsewhere, you have to do the following:

- Make a copy of the file `citrixhoneypot-launch.cfg.base`:

```bash
$ pwd
/home/citrix/CitrixHoneypot
cd etc
cp citrixhoneypot-launch.cfg.base citrixhoneypot-launch.cfg
cd ..
```

- Edit the file `/home/citrix/CitrixHoneypot/etc/citrixhoneypot-launch.cfg` and change the
  setting of the variable `CITRIX_VIRTUAL_ENV` to point to the directory where your
  virtual environment is.

Now you can launch the honeypot:

```bash
$ pwd
/home/citrix/CitrixHoneypot
./bin/citrixhoneypot start
Starting CitrixHoneypot ...
CitrixHoneypot is started successfully.
```

## Configure Additional Output Plugins (OPTIONAL)

CitrixHoneypot automatically outputs event data to text in `log/citrix.log`.
Additional output plugins can be configured to record the data other ways.
Supported output plugins include:

- JSON
- MySQL

More plugins are likely to be added in the future.

See `docs/[Output Plugin]/README.md` for details.

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

## Upgrading CitrixHoneypot

Updating is an easy process. First stop your honeypot. Then fetch any
available updates from the repository. As a final step upgrade your Python
dependencies and restart the honeypot:

```bash
./bin/citrixhoneypot stop
git pull
pip install --upgrade -r requirements.txt
./bin/citrixhoneypot start
```
