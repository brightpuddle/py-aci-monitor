"""Monitor ACI upgrade status

Author: Nathan Hemingway, Cisco Business Critical Services
Licence: Apache

This script is provided as is. No support is implied.

"""
from __future__ import print_function
from __future__ import with_statement
from pprint import pformat
from getpass import getpass
import time
import json
import sys
import os
import argparse
import traceback
# import websocket

# if sys.version_info[0] < 3:
#     print('This script requires python 3.')
#     exit()

DEPS = ['requests', 'termcolor']

try:
    import requests
    import urllib3  # type: ignore
    from termcolor import colored
    from requests.exceptions import ConnectionError, Timeout
except ModuleNotFoundError:
    print('Please "pip install" the following dependencies and try again:')
    for dep in DEPS:
        print(dep)
    exit()

if hasattr(__builtins__, 'raw_input'):
    input = __builtins__.raw_input

urllib3.disable_warnings()


def add1(x: int) -> int:
    return x + 1


add1("w00t")


def inline_progress(message, percent):  # type: (str, int) -> None
    """Print progress inline, overwriting current line"""
    sys.stdout.write(message % percent + '\r')
    sys.stdout.flush()


def logger(color):
    """Log results"""

    def _logger(header, data, *args):
        if isinstance(data, dict) or isinstance(data, list):
            print(colored('\n[%s]\n' % header, color), pformat(data))
        else:
            print(colored('[%s]' % header, color), data, *args)

    return _logger


log_i = logger('green')
log_w = logger('yellow')
log_e = logger('red')


class AuthException(Exception):
    pass


def Option(data):
    """Create option type"""
    if isinstance(data, Something):
        return data
    if data is not None:
        return Something(data)
    return Something(None)


class Something(object):
    """Option type wrapper for safe attribute access"""

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        if self.data is None:
            return 'Nothing'
        return 'Something(%s)' % self.data.__repr__()

    def __str__(self):
        return str(self.data)

    def __getitem__(self, key):
        try:
            return Something(self.data[key])
        except (KeyError, TypeError):
            return Something(None)

    def __iter__(self):
        if hasattr(self.data, '__iter__'):
            for x in self.data:
                if x is not None:
                    yield Option(x)

    def __nonzero__(self):
        return self.data is not None

    def __bool__(self):
        return self.data is not None

    def value(self):
        return self.data


class APIC(object):
    """APIC state data"""

    def __init__(self, options):
        self.options = options
        self.jar = None
        self.start_time = time.time()
        self.last_refresh = 0


def request(apic, method, relative_url, data={}):
    """Return raw requests result"""
    # TODO websocket would be more efficient
    # See ACItoolkit, acisession.py, line 275-ish
    url = 'https://%s%s.json' % (apic.options.ip, relative_url)
    if apic.options.verbose:
        log_i(method, url)
    if method == 'POST':
        return requests.post(
            url,
            cookies=apic.jar,
            data=json.dumps(data),
            verify=False,
            timeout=30)
    return requests.get(url, cookies=apic.jar, verify=False, timeout=30)


def get(apic, relative_url):  # type: (APIC, str) -> Something
    """Fetch and unwrap API request"""
    refresh_token(apic)
    res = request(apic, 'GET', relative_url)
    return Option(res.json())['imdata']


def login(apic):  # type: (APIC) -> APIC
    """Login to the APIC"""
    res = request(
        apic, 'POST', '/api/aaaLogin', {
            'aaaUser': {
                'attributes': {
                    'name': apic.options.usr,
                    'pwd': apic.options.pwd
                }
            }
        })
    if Option(res.json())['imdata'][0]['error']:
        raise AuthException('Authentication error.')
    apic.jar = res.cookies
    apic.last_refresh = time.time()
    return apic


def refresh_token(apic):  # type: (APIC) -> APIC
    """Check last token refresh and refresh if needed"""
    elapsed_time = time.time() - apic.last_refresh
    if elapsed_time > apic.options.token_refresh_interval:
        res = request(apic, 'GET', '/api/aaaRefresh')
        apic.jar = res.cookies
        apic.last_refresh = time.time()
    return apic


def get_options():  # type: () -> argparse.Namespace
    """Parse command line args."""
    DEFAULT_REQUEST_INTERVAL = 10
    DEFAULT_LOGIN_INTERVAL = 60
    DEFAULT_TOKEN_REFRESH = 60 * 8
    parser = argparse.ArgumentParser(description='Monitor ACI upgrade status.')
    parser.add_argument('-u', '--username', dest='usr', help='username')
    parser.add_argument('-p', '--password', dest='pwd', help='password')
    parser.add_argument(
        '-v', '--verbose', dest="verbose", action='store_true', help='verbose')
    parser.add_argument(
        '-s',
        '--snapshot',
        dest='snapshot',
        default='snapshot.json',
        help='snapshot filename (default snapshot.json)')
    parser.add_argument(
        '-d',
        '--debug',
        dest="debug",
        action='store_true',
        help='Debugging output (print all JSON)')
    parser.add_argument(
        '--request_interval',
        dest='request_interval',
        type=int,
        default=DEFAULT_REQUEST_INTERVAL,
        help='Interval between querying devices (default %ss)' %
        DEFAULT_REQUEST_INTERVAL)
    parser.add_argument(
        '--login_interval',
        dest='login_interval',
        type=int,
        default=DEFAULT_LOGIN_INTERVAL,
        help='Interval between APIC login attempts (default %ss)' %
        DEFAULT_LOGIN_INTERVAL)
    parser.add_argument(
        '--token_refresh_interval',
        dest='token_refresh_interval',
        type=int,
        default=DEFAULT_TOKEN_REFRESH,
        help='Seconds between token refresh (default %ss)' %
        DEFAULT_TOKEN_REFRESH)
    parser.add_argument('ip', help='APIC IP address')
    args = parser.parse_args()
    if not args.usr:
        args.usr = input('Username: ')  # type: ignore
    if not args.pwd:
        args.pwd = getpass('Password: ')
    if not args.ip:
        args.ip = input('APIC IP: ')
    return args


def get_devices(apic):  # type: (APIC) -> list(Something)
    """Get list of all devices on fabric."""
    devices = get(apic, '/api/class/topSystem')
    return [Option(d)['topSystem']['attributes'] for d in devices]


def get_apic_status(apic, device):  # type: (APIC, list(Something)) -> dict
    """Get APIC upgrade status."""
    dn = device['dn'].value()
    url_job = '/api/mo/%s/ctrlrfwstatuscont/upgjob' % dn
    url_running = '/api/mo/%s/ctrlrfwstatuscont/ctrlrrunning' % dn
    status = get(apic, url_job)[0]['maintUpgJob']['attributes']
    running = get(apic, url_running)[0]['firmwareCtrlrRunning']['attributes']
    return {'device': device, 'status': status, 'running': running}


def get_switch_status(apic, device):  # type: (APIC, list(Something)) -> dict
    """Get switch upgrade status."""
    dn = device['dn'].value()
    url_job = '/api/mo/%s/fwstatuscont/upgjob' % dn
    url_running = '/api/mo/%s/fwstatuscont/running' % dn
    status = get(apic, url_job)[0]['maintUpgJob']['attributes']
    running = get(apic, url_running)[0]['firmwareRunning']['attributes']
    return {'device': device, 'status': status, 'running': running}


def get_device_status(apic, devices):  # type (APIC, dict) -> dict
    """Upgrade status for any device type"""
    # TODO this should probably be threaded.
    # May take a while for a large fabric.
    result = []
    device_count = len(devices)
    for i, device in enumerate(devices):
        if device['role'].value() == 'controller':
            res = get_apic_status(apic, device)
        elif device['nodeType'].value() == 'virtual':
            # TODO support virtual leaf
            log_w('Unsupported Virtual Leaf', device['name'].value())
            continue
        elif device['nodeType'].value() == 'remote-leaf-wan':
            # TODO support remote leaf
            log_w('Unsupported Remote Leaf', device['name'].value())
            continue
        else:
            res = get_switch_status(apic, device)
        result.append(res)
        if apic.options.debug:
            name = device['name'].value()
            log_i('%s device info' % name, device.value())
            log_i('%s upgrade state' % name, res['status'].value())
            log_i('%s running state' % name, res['running'].value())
        else:
            query_percent = round(100 * (i / device_count))
            inline_progress('Querying devices: %d%%', query_percent)
    return result  # {device: ..., status: ..., running: ...}


def parse_upgrade_state(apic, status):  # type: (APIC, list(dict)) -> str
    """Parse and print upgrade status details."""
    scheduled_devices = []
    queued_devices = []
    upgrading_devices = []
    for device in status:
        # First determine how many devices are doing what...
        #
        # status =
        # | scheduled - upgrade scheduled (target version != current version)
        # | inqueue - node waiting to upgrade, e.g. 20 device limit, etc
        # | inprogress - upgrade is happening now
        # | waitonbootup - waiting for device to reboot
        # | completeok - completed successfully
        # Note that this is not an exhaustive list of states
        status = device['status']['upgradeStatus'].value()
        if status == 'scheduled':
            scheduled_devices.append(device)
        elif status == 'inqueue':
            queued_devices.append(device)
        elif status != 'completeok':
            upgrading_devices.append(device)
    if len(scheduled_devices) > 0:
        log_i('Status',
              '%d device(s) scheduled for upgrade.' % len(scheduled_devices))
        print('Note, that these will not start upgrading without a trigger.')
        if not apic.options.verbose:
            print('Use "verbose" option to view details of scheduled devices.')
        else:
            for device in scheduled_devices:
                ip = device['device']['address'].value()
                name = device['device']['name'].value()
                log_i(
                    '%s %s' % (name, ip), {
                        'Firmware group':
                        device['status']['fwGrp'].value(),
                        'Current version':
                        device['running']['version'].value(),
                        'Target version':
                        device['status']['desiredVersion'].value(),
                        'Maintenance group':
                        device['status']['maintGrp'].value(),
                    })
    if len(queued_devices) > 0:
        log_w('Status',
              '%d device(s) queued for upgrade.' % len(queued_devices))
        print('These devices are queued to upgrade automatically...')
        for device in queued_devices:
            ip = device['device']['address'].value()
            name = device['device']['name'].value()
            log_w(
                '%s %s' % (name, ip), {
                    'Firmware group': device['status']['fwGrp'].value(),
                    'Current version': device['running']['version'].value(),
                    'Target version':
                    device['status']['desiredVersion'].value(),
                    'Maintenance group': device['status']['maintGrp'].value(),
                })
    if len(upgrading_devices) > 0:
        log_w('Status', '%d device(s) upgrading.' % len(upgrading_devices))
        percents = []
        for device in upgrading_devices:
            ip = device['device']['address'].value()
            name = device['device']['name'].value()
            percent = device['status']['instlProgPct'].value()
            try:
                percents.append(int(percent))
            except TypeError:
                pass
            log_w(
                '%s %s' % (name, ip), {
                    'Status:': device['status']['upgradeStatusStr'].value(),
                    'Percent complete':
                    device['status']['instlProgPct'].value(),
                    'Firmware group': device['status']['fwGrp'].value(),
                    'Current version': device['running']['version'].value(),
                    'Target version':
                    device['status']['desiredVersion'].value(),
                    'Maintenance group': device['status']['maintGrp'].value(),
                })
        if len(percents) > 0:
            average_percent = round(sum(percents) / len(percents))
            log_i('Status', 'Average total percent: %d%%' % average_percent)
    if len(queued_devices) == 0 and len(upgrading_devices) == 0:
        log_i('Status', 'No devices currently undergoing upgrade.')
        return 'stable'
    return 'upgrading'


def get_faults(apic):  # type: (APIC) -> list(Something)
    """Get fault list w/ details."""
    faults = get(apic, '/api/class/faultInfo')
    return [fault['faultInst']['attributes'] for fault in faults]


def load_snapshot(apic):  # type: (APIC) -> list(Something)
    """Load/create snapshot"""
    fn = apic.options.snapshot
    faults = get_faults(apic)
    if not os.path.isfile(fn):
        with open(fn, 'w') as f:
            log_i('Snapshot', 'Creating new snapshot %s...' % fn)
            f.write(json.dumps([fault.value() for fault in faults]))
            return faults
    with open(fn, 'r') as f:
        log_i('Snapshot', 'Loading snapshot %s...' % fn)
        return [Something(fault) for fault in json.loads(f.read())]


def request_loop(apic, devices):  # type: (APIC, list(Something)) -> None
    """Monitor status."""
    while True:
        results = get_device_status(apic, devices)
        upgrade_state = parse_upgrade_state(apic, results)
        if upgrade_state == 'stable':
            get_faults(apic, devices)
        elapsed_time = round(time.time() - apic.start_time)
        if apic.options.verbose:
            log_i('Timer', 'Total run time: %d seconds.' % elapsed_time)
        log_i('Timer',
              'Sleeping for %s seconds...' % apic.options.request_interval)
        time.sleep(apic.options.request_interval)


def main_loop(apic):  # type: (APIC) -> None
    """Login and handle connecitivity exceptions."""
    devices = get_devices(apic)
    while True:
        try:
            apic.login()
            request_loop(apic, devices)
        except ConnectionError:
            log_w('Connection Failed', 'Trying again...')
            print('Note: this is expected on device restart.')
            log_i(
                'Timer', 'Waiting %s seconds before trying again...' %
                apic.options.login_interval)
            time.sleep(apic.options.login_interval)
        except Timeout:
            log_w('Connection Timeout',
                  'Connection timeout. Attempting reconnect...')
        except AuthException:
            log_w('Authentication Failed', 'Trying again...')
            print('Note: this is expected when the APIC first boots.')


def main():  # type: () -> None
    """Initial entry and top-level exception handling."""
    while True:
        try:
            apic = login(APIC(get_options()))
            #
            #
            #
            main_loop(apic)
        except KeyboardInterrupt:
            exit()
        except ConnectionError:
            log_e('Connection Failed',
                  'Please check the IP address and try again.')
            exit()
        except AuthException:
            log_e('Authentication Failed',
                  'Please check your credentials and try again.')
            exit()
        except Exception as e:
            # Run forever unless intentionally failing
            WAIT = 10
            log_e('Unexpected Error', str(e))
            traceback.print_exc()
            print('Trying again in %d seconds...' % WAIT)
            time.sleep(WAIT)


if __name__ == '__main__':
    main()
