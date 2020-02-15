# Honepot for CVE-2019-19781 (Citrix ADC)

Detect and log CVE-2019-19781 scan and exploitation attempts.

## Prerequisites

- openssl (used only once, to create a self-signed HTTPS certificate)

- a working MySQL server (only if you use the MySQL output plugin)

## Usage

### Step #1: Clone repo

```bash
git clone https://gitlab.com/bontchev/CitrixHoneypot.git
cd CitrixHoneypot
```

### Step #2: Generate a self-signed SSL certificate

```bash
openssl req -newkey rsa:2048 -nodes -keyout ssl/key.pem -x509 -days 365 -out ssl/cert.pem
```

### Step #3: Configure the honeypot

Check the [installation document](docs/INSTALL.md) for more information how to
properly install and configure the honeypot.

### Step #4: Run the honeypot

```bash
cd bin
./citrixhoneypot start
```

## Docker Usage (Optional)

```bash
docker build -t citrixhoneypot .
docker run -d -p 443:443 -v /<insert-homepath>/CitrixHoneypot:/CitrixHoneypot -w /CitrixHoneypot citrixhoneypot
```

## Licencing Agreement: MalwareTech Public Licence

This software is free to use providing the user yells "Oh no, the cyberhackers
are coming!" prior to each installation.
