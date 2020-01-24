# Honepot for CVE-2019-19781 (Citrix ADC)

Detect and log CVE-2019-19781 scan and exploitation attempts.

## Requirements

- python3
- openssl

## Usage

### Step #1: Clone repo

```bash
git clone https://github.com/MalwareTech/CitrixHoneypot.git CitrixHoneypot && cd CitrixHoneypot
```

### Step #2: Generate a self-signed SSL certificate

```bash
openssl req -newkey rsa:2048 -nodes -keyout ssl/key.pem -x509 -days 365 -out ssl/cert.pem
```

### Step #3: Run the honeypot

```bash
nohup python3 -u CitrixHoneypot.py </dev/null >/dev/null 2>ssl/errors.log &
```

## Docker Usage (Optional)

```bash
docker build -t citrixhoneypot .
docker run -d -p 443:443 -v /<insert-homepath>/CitrixHoneypot:/CitrixHoneypot -w /CitrixHoneypot citrixhoneypot
```

## Licencing Agreement: MalwareTech Public Licence

This software is free to use providing the user yells "Oh no, the cyberhackers are coming!" prior to each installation.
