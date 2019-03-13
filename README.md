# Cisco ACI tools

A collection of various tools to work with Cisco ACI.

## Upgrade Monitor (upgrade_monitor.py)

Monitor upgrade status of the ACI fabric.

**Requirements:**
```
pip install requests termcolor
```

**Usage:**
```
aci-github $ python upgrade_monitor.py -h
usage: upgrade_monitor.py [-h] [-u USR] [-p PWD] [-v] [-d]
                          [--request_interval REQUEST_INTERVAL]
                          [--login_interval LOGIN_INTERVAL]
                          [--token_refresh_interval TOKEN_REFRESH_INTERVAL]
                          ip

Monitor ACI upgrade status.

positional arguments:
  ip                    APIC IP address

optional arguments:
  -h, --help            show this help message and exit
  -u USR, --username USR
                        username
  -p PWD, --password PWD
                        password
  -v, --verbose         verbose
  -d, --debug           Debugging output
  --request_interval REQUEST_INTERVAL
                        Interval between querying devices (seconds)
  --login_interval LOGIN_INTERVAL
                        Interval between APIC login attempts (seconds)
  --token_refresh_interval TOKEN_REFRESH_INTERVAL
                        Seconds between token refresh
```

## Scalability analysis (scale.py)

This script checks scalability metrics. As of ACI software 3.x, the scalability dashboard capabilities largely overlap with the script, though, not entirely. Additional checks may be added in the future.

**Requirements:**

* ACI Cobra SDK (downloadable egg from the APIC)
* termcolor

Tested under Python 2.7.11, but it should be compatible with Python 3.

**Usage:**

```
aci-github $ python scale.py --help
usage: scale [-h] [-v]

Scalability assessment

optional arguments:
  -h, --help               show this help message and exit
  -o FILE, --output FILE   Output filename (default: stdout)
  -v, --verbose            Verbose
```

The verbose option prints the raw data used to derive the scalability metrics.
