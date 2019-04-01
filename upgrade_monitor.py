from __future__ import print_function
from getpass import getpass
from pprint import pformat
import argparse
import json
import os
import sys
import time
import traceback
# import websocket

DEPS = ['requests', 'termcolor', 'colorama']

try:
    import requests
    import urllib3  # type: ignore
    from termcolor import colored
    from requests.exceptions import ConnectionError, Timeout
    import colorama  # type: ignore
except ImportError:
    print('Please "pip install" the following dependencies and try again:')
    for dep in DEPS:
        print(dep)
    exit()

if hasattr(__builtins__, 'raw_input'):  # type: ignore
    compat_input = __builtins__.raw_input
else:
    compat_input = input

urllib3.disable_warnings()
colorama.init()


def logger(color):
    """Log results"""

    def _logger(header, data, *args):
        if isinstance(data, dict) or isinstance(data, list):
            print(colored('\n[%s]\n' % header, color), pformat(data))
        elif isinstance(data, str):
            print(colored('[%s]' % header, color), data, *args)

    return _logger


log_i = logger('green')
log_w = logger('yellow')
log_e = logger('red')


class AuthException(Exception):
    pass


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


def Option(data):
    """Create option type"""
    if isinstance(data, Something):
        return data
    if data is not None:
        return Something(data)
    return Something(None)


class APIC(object):
    """APIC state data"""

    def __init__(self, options):
        self.options = options
        self.jar = None
        self.start_time = time.time()
        self.faults = []  # type: list[str]
        self.devices = []  # type: list[Something]
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


def get(apic, relative_url):
    # type: (APIC, str) -> Something
    """Fetch and unwrap API request"""
    refresh_token(apic)
    res = request(apic, 'GET', relative_url)
    return Option(res.json())['imdata']


def login(apic):
    # type: (APIC) -> APIC
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


def refresh_token(apic):
    # type: (APIC) -> APIC
    """Check last token refresh and refresh if needed"""
    elapsed_time = time.time() - apic.last_refresh
    if elapsed_time > apic.options.token_refresh_interval:
        res = request(apic, 'GET', '/api/aaaRefresh')
        apic.jar = res.cookies
        apic.last_refresh = time.time()
    return apic


def get_options():
    # type: () -> argparse.Namespace
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
        args.usr = input('Username: ')
    if not args.pwd:
        args.pwd = getpass('Password: ')
    if not args.ip:
        args.ip = input('APIC IP: ')
    return args


def get_devices(apic):
    # type: (APIC) -> list[Something]
    """Get list of all devices on fabric."""
    devices = get(apic, '/api/class/topSystem')
    return [d['topSystem']['attributes'] for d in devices]


def get_apic_status(apic, device):
    # type: (APIC, Something) -> dict[str, Something]
    """Get APIC upgrade status."""
    dn = device['dn'].value()
    url_job = '/api/mo/%s/ctrlrfwstatuscont/upgjob' % dn
    url_running = '/api/mo/%s/ctrlrfwstatuscont/ctrlrrunning' % dn
    status = get(apic, url_job)[0]['maintUpgJob']['attributes']
    running = get(apic, url_running)[0]['firmwareCtrlrRunning']['attributes']
    return {'device': device, 'status': status, 'running': running}


def get_switch_status(apic, device):
    # type: (APIC, Something) -> dict[str, Something]
    """Get switch upgrade status."""
    dn = device['dn'].value()
    url_job = '/api/mo/%s/fwstatuscont/upgjob' % dn
    url_running = '/api/mo/%s/fwstatuscont/running' % dn
    status = get(apic, url_job)[0]['maintUpgJob']['attributes']
    running = get(apic, url_running)[0]['firmwareRunning']['attributes']
    return {'device': device, 'status': status, 'running': running}


def get_device_status(apic):
    # type: (APIC) -> list[dict[str, Something]]
    """Upgrade status for any device type"""
    # TODO this should probably be threaded.
    # May take a while for a large fabric.
    result = []
    device_count = len(apic.devices)
    for i, device in enumerate(apic.devices):
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
            query_percent = round(100 * (float(i) / device_count))
            print('Querying devices: %d%%\r' % query_percent, end='')
            sys.stdout.flush()
    return result  # list[{device: ..., status: ..., running: ...}]


def parse_upgrade_state(apic, status):
    # type: (APIC, list[dict[str, Something]]) -> str
    """Parse and print upgrade status details."""
    scheduled_devices = []
    queued_devices = []
    upgrading_devices = []
    unavailable_devices = []
    for device in status:
        # First determine how many devices are doing what...
        #
        # device['status'] =
        # | scheduled - upgrade scheduled (target version != current version)
        # | inqueue - node waiting to upgrade, e.g. 20 device limit, etc
        # | inprogress - upgrade is happening now
        # | waitonbootup - waiting for device to reboot
        # | completeok - completed successfully
        # Note that this is not an exhaustive list of states
        state = device['status']['upgradeStatus'].value()
        if state == 'scheduled':
            scheduled_devices.append(device)
        elif state == 'inqueue':
            queued_devices.append(device)
        elif state is None:
            unavailable_devices.append(device)
        elif state != 'completeok':
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
    if len(unavailable_devices) > 0:
        log_w(
            'Status', '%d device(s) are not providing a current status.' %
            len(unavailable_devices))
        print(
            'Devices may be rebooting due to upgrade or other maintenance work.'
        )
        for device in unavailable_devices:
            ip = device['device']['address'].value()
            name = device['device']['name'].value()
            log_w('%s %s' % (name, ip), 'Unavailable.')
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
    if len(queued_devices) == 0 and len(upgrading_devices) == 0 and len(
            unavailable_devices) == 0:
        log_i('Status', 'No devices currently undergoing upgrade.')
        return 'stable'
    return 'upgrading'


def get_faults(apic):
    # type: (APIC) -> list[Something]
    """Get fault list w/ details."""
    faults = get(apic, '/api/class/faultInfo')
    result = []
    for fault in faults:
        fault_attributes = fault['faultInst']['attributes']
        if fault_attributes.value() is not None:
            result.append(fault_attributes)
    return result


def load_snapshot(apic):
    # type: (APIC) -> APIC
    """Load/create snapshot"""
    fn = apic.options.snapshot
    if not os.path.isfile(fn):
        with open(fn, 'w') as f:
            log_i('Snapshot', 'Creating new snapshot %s...' % fn)
            apic.faults = get_faults(apic)
            apic.devices = get_devices(apic)
            to_file = {
                'faults': [f.value() for f in apic.faults],
                'devices': [d.value() for d in apic.devices]
            }
            f.write(json.dumps(to_file, indent=2))
    else:
        with open(fn, 'r') as f:
            log_i('Snapshot', 'Loading snapshot %s...' % fn)
            snapshot = json.loads(f.read())
            apic.faults = [Option(f) for f in snapshot.get('faults', [])]
            apic.devices = [Option(d) for d in snapshot.get('devices', [])]
    # defensive file reading
    apic.faults = apic.faults if isinstance(apic.faults, list) else []
    apic.devices = apic.devices if isinstance(apic.devices, list) else []
    return apic


def check_faults(apic):
    # type: (APIC) -> None
    new_faults = []
    for current_fault in get_faults(apic):
        new_fault = True
        for previous_fault in apic.faults:
            if previous_fault['dn'].value() == current_fault['dn'].value():
                new_fault = False
        if new_fault and current_fault['severity'].value() != 'cleared':
            new_faults.append(current_fault)
    if len(new_faults) > 0:
        log_w('Fault Status',
              '%s new fault(s) since previous snapshot.' % len(new_faults))
        for fault in new_faults:
            if apic.options.debug:
                log_w('New Fault: %s' % fault['code'].value(), fault.value())
            else:
                log_w(
                    'New Fault: %s' % fault['code'].value(), {
                        'dn': fault['dn'].value(),
                        'severity': fault['severity'].value(),
                        'description': fault['description'].value(),
                    })

    else:
        log_i('Fault Status', 'No new faults since snapshot.')


def request_loop(apic):
    # type: (APIC) -> None
    """Monitor status."""
    while True:
        results = get_device_status(apic)
        upgrade_state = parse_upgrade_state(apic, results)
        if upgrade_state == 'stable':
            check_faults(apic)
        elapsed_time = round(time.time() - apic.start_time)
        if apic.options.verbose:
            log_i('Timer', 'Total run time: %d seconds.' % elapsed_time)
        log_i('Timer',
              'Sleeping for %s seconds...' % apic.options.request_interval)
        time.sleep(apic.options.request_interval)


def main_loop(apic):
    # type: (APIC) -> None
    """Login and handle connecitivity exceptions."""
    while True:
        try:
            login(apic)
            request_loop(apic)
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


def main():
    # type: () -> None
    """Initial entry and top-level exception handling."""
    while True:
        try:
            apic = APIC(get_options())
            apic = login(apic)
            apic = load_snapshot(apic)
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
            # Run forever unless Ctrl-C, etc
            WAIT = 10
            log_e('Unexpected Error', str(e))
            traceback.print_exc()
            print('Trying again in %d seconds...' % WAIT)
            time.sleep(WAIT)


if __name__ == '__main__':
    main()
