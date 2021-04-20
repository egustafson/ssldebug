# ssl-debug - An SSL Diagnostic Tool

A simple Client side SSL diagnostic tool.  It attempts to establish an
SSL connection to a remote endpoint in a step wise manner; reporting
the progress at each step.

## Usage:

```
> ssldebug -h
usage: ssldebug.py [-h] [-v] [--hostname HOSTNAME] [--ca CA] [--cert CERT] [--key KEY] [--alpn ALPN] hostport

positional arguments:
  hostport             Hostname:Port of SSL service

optional arguments:
  -h, --help           show this help message and exit
  -v, --verbose        verbose output
  --hostname HOSTNAME  TLS hostname
  --ca CA              CA file
  --cert CERT          Cert (chain) file
  --key KEY            Key file
  --alpn ALPN          ALPN String
```
