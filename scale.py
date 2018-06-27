"""Scalability script

Gathers scalability metrics from APIC for comparison with scalability guide.

Based on 3.0 scalability guide.
Adjust the second variable to the "result" function to change the threshold.
"""
from __future__ import print_function
from collections import Counter
from pprint import pprint
from getpass import getpass
import argparse
from termcolor import colored
from cobra.mit.access import MoDirectory
from cobra.mit.session import LoginSession
from cobra.mit.naming import Dn

TESTS = []

verbose = False

SCALE_OK = 1
SCALE_WARNING = 2
SCALE_ERROR = 3
THRESHOLD = .75


###############################################################################
# General
###############################################################################

parser = argparse.ArgumentParser(prog='scale', 
        description='Scalability assessment')
parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')


def dn(object, count=0):
    result = object if type(object) == Dn else object.dn
    while count:
        result = result.getParent()
        count -= 1
    return str(result)


def enabled(_fn):
    """Add test to test runner."""
    TESTS.append(_fn)
    return _fn


def login():
    """Login to the APIC"""
    apic = raw_input('APIC URL (e.g. http://10.1.1.1): ')
    user = raw_input('Username: ')
    password = getpass('Password: ')
    session = LoginSession(apic, user, password, secure=False)
    modir = MoDirectory(session)
    modir.login()
    return modir


def result(count, limit, detail):
    """Print the test results and return true for pass"""
    threshold = float(count) / limit
    print('{} of {} - {}%'.format(count, limit, round(threshold * 100, 2)))
    if globals()['verbose']:
        pprint(detail)
    if count >= limit:
        return SCALE_ERROR
    if threshold >= THRESHOLD:
        return SCALE_WARNING
    return SCALE_OK


###############################################################################
# Fabric Scale
###############################################################################


@enabled
def get_apics(modir):
    """Total APIC count"""
    nodes = modir.lookupByClass('fabricNode')
    apics = [node for node in nodes if node.role == 'controller']
    return result(len(apics), 5, [dn(apic) for apic in apics])


@enabled
def get_bds(modir):
    """Total BD count"""
    bds = modir.lookupByClass('fvBD')
    return result(bds.totalCount, 15000, [dn(bd) for bd in bds])


@enabled
def get_tenants(modir):
    """Total tenant count"""
    tenants = modir.lookupByClass('fvTenant')
    return result(tenants.totalCount, 3000,
            [dn(tenant) for tenant in tenants])


@enabled
def get_epgs(modir):
    """Total EPG count"""
    epgs = modir.lookupByClass('fvAEPg')
    return result(epgs.totalCount, 15000, [dn(epg) for epg in epgs])


@enabled
def get_eps(modir):
    """Total EP count"""
    ceps = modir.lookupByClass('fvCEp')
    eps = modir.lookupByClass('fvIp')
    total = ceps.totalCount + eps.totalCount
    detail = ([dn(ep) for ep in ceps], [dn(ep) for ep in eps])
    return result(total, 180000, detail)


@enabled
def get_contracts(modir):
    """Total contract count"""
    contracts = modir.lookupByClass('vzBrCP')
    return result(contracts.totalCount, 2000,
            [dn(contract) for contract in contracts])


@enabled
def get_filters(modir):
    """Total filter count"""
    flts = modir.lookupByClass('vzFilter')
    return result(flts.totalCount, 10000, [dn(flt) for flt in flts])


@enabled
def get_ip_per_mac(modir):
    """IPs per MAC"""
    mac_ip_pairs = {(ep.mac, ep.ip) for ep in modir.lookupByClass('fvEp')}
    counter = Counter([mac for mac, _ip in mac_ip_pairs])
    return result(len(counter), 1024, mac_ip_pairs)


@enabled
def get_ipv4_prefix(modir):
    """Total IPv4 prefixes (no IPv6)"""
    prefixes = modir.lookupByClass('actrlPfxEntry')
    return result(prefixes.totalCount, 40000,
            [dn(prefix) for prefix in prefixes])


@enabled
def get_leaves(modir):
    """Total leaf count"""
    nodes = modir.lookupByClass('fabricNode')
    leaves = [node for node in nodes if node.role == 'leaf']
    # Pod name for per pod metrics:
    # dn(leaf).split('/')[1]
    return result(len(leaves), 80, [dn(leaf) for leaf in leaves])


@enabled
def get_spines(modir):
    """Total spine count"""
    nodes = modir.lookupByClass('fabricNode')
    spines = [node for node in nodes if node.role == 'spine']
    # Pod name for per pod metrics:
    # dn(spine).split('/')[1]
    return result(len(spines), 6, [dn(spine) for spine in spines])


@enabled
def get_mac_epgs(modir):
    """Total MAC EPG count"""
    epgs = [dn(epg) for epg in modir.lookupByClass('fvAEPg')
            if epg.pcEnfPref == 'enforced']
    return result(len(epgs), 125, epgs)


def get_multicast_groups():
    """Total multicast groups"""


@enabled
def get_l3_sessions(modir):
    """OSPF + BGP session count"""
    ospf = modir.lookupByClass('ospfAdjEp')
    bgp = modir.lookupByClass('bgpPeer')
    return result(ospf.totalCount + bgp.totalCount, 1200, {
        'ospf': [dn(o) for o in ospf],
        'bgp': [dn(b) for b in bgp],
        })


@enabled
def get_vrfs(modir):
    """Total VRF count"""
    vrfs = modir.lookupByClass('fvCtx')
    return result(vrfs.totalCount, 1000, [dn(vrf) for vrf in vrfs])


###############################################################################
# Per Leaf Scale
###############################################################################


def get_arp_per_l3out_per_leaf(_modir):
    """Per leaf: ARPs per L3Out"""
    # l3outs = modir.lookupByClass('l3extOut')


@enabled
def get_bds_per_leaf(modir):
    """Per leaf: BD count"""
    bds = modir.lookupByClass('l2BD')
    leaves = Counter((dn(bd, 2) for bd in bds))
    results = (result(count, 3500, leaf) for leaf, count in leaves.items())
    return reduce(lambda x, y: x and y, results)


def get_encap_per_port_per_leaf(_modir):
    """Per leaf: Encaps/port"""


def get_encap_per_fex_per_leaf(_modir):
    """Per leaf: Encaps/FEX PC or VPC"""


def get_ipv4_ep_per_leaf(_modir):
    """Per leaf: IPv4 EP count"""


@enabled
def get_mac_ep_per_leaf(modir):
    """Per leaf: MAC EP count"""
    leaves = modir.lookupByClass('eqptcapacityL2Usage5min')
    results = (result(
        int(leaf.localEpCum),
        int(leaf.localEpCapCum),
        dn(leaf, 3))
        for leaf in leaves if int(leaf.localEpCapCum) > 0)
    return reduce(lambda x, y: x and y, results)


def get_fex_per_leaf(_modir):
    """Per leaf: FEX count"""


def get_fex_ports_per_leaf(_modir):
    """Per leaf: FEX port count"""


def get_ipv4_prefix_per_leaf(modir):
    """Per leaf: IPv4 prefix count"""
    leaves = modir.lookupByClass('eqptcapacityL3Usage5min')
    # Scalability dashboard is pulling 12288 from the switch
    # Guide says 20000
    results = (result(leaf.localEpCum, 12288, dn(leaf, 3))
        for leaf in leaves)
    return reduce(lambda x, y: x and y, results)


def get_pc_per_leaf(_modir):
    """Per leaf: PC count"""


def get_port_vlan_per_leaf(_modir):
    """Per leaf: Ports * VLANs (FEX HIF)"""
    "eqptcapacityVlanUsage5min"


def get_tcam_per_leaf(modir):
    """Per leaf: TCAM size"""
    epgs = modir.lookupByClass('fvEpP')
    return epgs


@enabled
def get_vrfs_per_leaf(modir):
    """Per leaf: VRF count"""
    vrfs = modir.lookupByClass('l3Dom')
    leaves = Counter((dn(vrf, 2) for vrf in vrfs))
    results = (result(count, 400, leaf) for leaf, count in leaves.items())
    return reduce(lambda x, y: x and y, results)


###############################################################################
# Per VRF Scale
###############################################################################

@enabled
def get_bds_per_vrf(modir):
    """Per VRF: BD count"""
    bds = modir.lookupByClass('fvRtCtx')
    vrf_bd_pairs = {(dn(bd, 1), dn(bd)) for bd in bds}
    counter = Counter([vrf for vrf, bd in vrf_bd_pairs])
    return result(len(counter), 256, vrf_bd_pairs)


def get_multicast_groups_per_vrf(_modir):
    """Per VRF: Multicast groups"""


###############################################################################
# Main
###############################################################################


def run_tests(tests, modir):
    """Main test runner"""
    for test in tests:
        print('\n', colored(test.__doc__ + '\n' + ('=' * 60), 'green'))
        scale_status = test(modir)
        if scale_status == SCALE_WARNING:
            print(colored('Approaching scale limit', 'yellow'))
        if scale_status == SCALE_ERROR:
            print(colored('Over scale', 'red'))


def main():
    """Main entry"""
    try:
        args = parser.parse_args()
        if args.verbose:
            globals()['verbose'] = True
        modir = login()
        run_tests(TESTS, modir)
    except KeyboardInterrupt:
        exit()


if __name__ == '__main__':
    main()
