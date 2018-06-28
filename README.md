# Cisco ACI tools

A collection of various tools to work with Cisco ACI.

## Scalability analysis (scale.py

This script checks scalability metrics. As of ACI software 3.x, the scalability dashboard capabilities largely overlap with the script, though, not entirely. Additional checks may be added in the future.

**Requirements:**

* ACI Cobra SDK (downloadable egg from the APIC)
* termcolor

Tested under Python 2.7.11, but it should be compatible with Python 3.

**Options:**

-v --verbose -- Verbose output. Prints the raw data used to derive the scale metrics.
-h --help -- Print usage info.
