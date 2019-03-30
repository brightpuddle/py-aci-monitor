# ACI upgrade status monitor

**NOTE** This tool was ported to Go. The Go version provides pre-built, cross-platform binaries, has no dependencies, and runs significantly faster than this version. Unless integrating this into existing Python tooling, it's recommended to use the binary version.

https://github.com/brightpuddle/aci-monitor



This tool was originally developed to monitor the status of the upgrade status of Cisco ACI fabric. In addition to monitoring upgrade-specific status, it performs a snapshot/compare functionality to check for a change in fault state. Faults are triggered for a wide variety of events, including ISIS adjacency issues, internal MP-BGP adjancencies, COOP sync, etc. Because of this, it may also be useful as a general pre/post check tool to ensure network health throughout, and at the end of any ACI changes.


## Requirements
Python (v2 or v3).

```
pip install requests termcolor colorama
```

## Usage
```
aci-github $ python upgrade_monitor.py -h
usage: upgrade_monitor.py [-h] [-u USR] [-p PWD] [-v] [-s SNAPSHOT] [-d]
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
  -s SNAPSHOT, --snapshot SNAPSHOT
                        snapshot filename (default snapshot.json)
  -d, --debug           Debugging output (print all JSON)
  --request_interval REQUEST_INTERVAL
                        Interval between querying devices (default 10s)
  --login_interval LOGIN_INTERVAL
                        Interval between APIC login attempts (default 60s)
  --token_refresh_interval TOKEN_REFRESH_INTERVAL
                        Seconds between token refresh (default 480s)
```

The only mandatory command line parameter is the IP address of the APIC. The script will assume HTTPS (hardcoded) and will accomodate invalid certificates. All other mandatory parameters, i.e. username and password, can be passed as parameters or will be prompted for.

The first time the script is run it will create a snapshot file (`snapshot.json` by default). This file contains the list of devices on the fabric and the current fault list. Once the upgrade status is considered stable, i.e. no devices are actively upgrading, the faults and expected devices will be queried to ensure:

1. All devices in the snapshot are still available to the fabric
2. No additional faults have been raised

I'd recommend backing up the snapshot.json file and creating a new one before any change. This will provide a pre-change baseline to ensure the script has the most up-to-date information, and isn't comparing against the incorrect status.

## Timers
The default timers should work for most cases, but are explained below.

**REQUEST_INTERVAL**
This is the sleep time between querying all devices on the fabric. The script will make two sequential requests to each device on the fabric, query the fault list (if appropriate), and then sleep for `REQUEST_INTERVAL` before repeating this process.

**LOGIN_INTERVAL**
This is the time between login attempts with authentication to the APIC fails. An initial failed authentication attempt, e.g. a mistyped password, will terminate the script. This timer is used for when the script is already running and the APIC goes offline due to maintenance activity.

**TOKEN_REFRESH_INTERVAL**
This is verified at the start of each request, and if the interval has been exceeded, the login token is refreshed. The default timeout is 10 minutes, so the default refresh interval of 8 minutes should work for most cases. In the worst case, if the token expires, login will fail, and the script will attempt to login again, retrying every `LOGIN_INTERVAL`.

