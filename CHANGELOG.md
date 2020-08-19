# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.3]

### Changed in version 2.0.3

* Nothing yet

### Added in version 2.0.3

* Nothing yet

## [2.0.2]

### Changed in version 2.0.2

* Now handling custom HTTP requests, not just HEAD, GET, and POST
* Fixed an error in the MySQL plugin error handler
* Improved the `Dockerfile`
* Minor optimizations

## [2.0.1]

### Changed in version 2.0.1

* Fixed a bug when responding to certain requests

## [2.0.0]

### Added in version 2.0.0

* A script for starting, stopping, and restarting the honeypot
* Config file support
* Various command-line options
* HEAD requests are now logged too
* Output plugin support
* Output plugin for JSON
* Output plugin for MySQL
* Log rotation

### Changed in version 2.0.0

* Made the script compatible with Python 2.7
* The HTTPS server and the logging now use the Twisted framework
* Rewrote the documentation
