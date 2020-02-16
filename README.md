# Honepot for CVE-2019-19781 (Citrix ADC)

Detect and log CVE-2019-19781 scan and exploitation attempts. Based on
[MalwareTech's Citrix honeypot](https://github.com/MalwareTech/CitrixHoneypot)
but heavily rewritten.

## Prerequisites

- openssl (used only once, to create a self-signed HTTPS certificate)

- a working MySQL server (only if you use the MySQL output plugin)

## Usage

Check the [installation document](docs/INSTALL.md) for more information how to
properly install, configure, and run the honeypot.

## Licencing Agreement: MalwareTech Public Licence

This software is free to use providing the user yells "Oh no, the cyberhackers
are coming!" prior to each installation.
