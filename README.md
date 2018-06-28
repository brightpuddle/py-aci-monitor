# Cisco ACI tools

A collection of various tools to work with Cisco ACI.

## Scalability analysis (scale.py

This script checks scalability metrics. As of ACI software 3.x, the scalability dashboard capabilities largely overlap with the script, though, not entirely. Additional checks may be added in the future.

**Requirements:**

* ACI Cobra SDK (downloadable egg from the APIC)
* termcolor

Tested under Python 2.7.11, but it should be compatible with Python 3.

**Options:**

```
aci $ python scale.py --help
usage: scale [-h] [-v]

Scalability assessment

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Verbose
```

The verbose option prints the raw data used to derive the scalability metrics.
