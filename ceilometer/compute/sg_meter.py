import subprocess
from eventlet import greenthread
import collections

INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
SG_CHAIN = 'sg-chain'
SPOOF_FILTER = 'spoof-filter'
CHAIN_PREFIX = 'neutron-openvswi-'
CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o',
                     SPOOF_FILTER: 's'}
MAX_CHAIN_LEN_NOWRAP = 28


SGPortData = collections.namedtuple(
    'SGPort',
    ['in_drop_bytes', 'in_drop_packets', 'in_accept_bytes', 'in_accept_packets',
     'out_drop_bytes', 'out_drop_packets', 'out_accept_bytes', 'out_accept_packets']
)

def execute(cmd):
    try:
        obj = subprocess.Popen(cmd,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=False)
        _stdout, _stderr = obj.communicate()
        returncode = obj.returncode
        obj.stdin.close()
    finally:
        # NOTE(termie): this appears to be necessary to let the subprocess
        #               call clean something up in between calls, without
        #               it two execute calls in a row hangs the second one
        greenthread.sleep(0)

    return _stdout

def _get_counters(chain_lines):
    counter = {'acc_pkts': 0, 'acc_bytes': 0 , 'drop_pkts': 0, 'drop_bytes':0}
    for line in chain_lines:
        if not line:
            break
        data = line.split()
        if (len(data) < 2 or
                not data[0].isdigit() or
                not data[1].isdigit()):
            break
        if data[2] == 'RETURN':
            counter['acc_pkts'] += int(data[0])
            counter['acc_bytes'] += int(data[1])
        elif data[2] == 'DROP' or data[2] == 'neutron-openvswi-sg-fallback':
            counter['drop_pkts'] += int(data[0])
            counter['drop_bytes'] += int(data[1])
        else:
            pass
        return counter

def _get_iptables_info(zero=True):

    non_field = ['neutron-openvswi-FORWARD', 'neutron-openvswi-INPUT',
         'neutron-openvswi-OUTPUT', 'neutron-openvswi-local',
         'neutron-openvswi-sg-chain', 'neutron-openvswi-sg-fallback']

    chain_counters = {}
    cmd = "iptables"
    args = ['sudo', cmd,  '-L', '-n', '-v', '-x']
    if zero:
        args.append('-Z')
    current_text = execute(args)
    chain_list = current_text.split('\n\n')
    for chain_info in chain_list:
        chain_lines = chain_info.split('\n')
        chain_name = chain_lines[0].split(' ')[1]

        if CHAIN_PREFIX in chain_name and chain_name not in non_field:
            if chain_name[len(CHAIN_PREFIX)] in ['i', 'o', 's']:
                chain_counters[chain_name] = _get_counters(chain_lines[2:])
    return chain_counters

def _get_port_chain_name(port, direction):
    return ('%s%s%s' % (CHAIN_PREFIX, CHAIN_NAME_PREFIX[direction], port))[:MAX_CHAIN_LEN_NOWRAP]

# Get SG info.
def get_sg_cache(ports, cache):
    chain_counters = _get_iptables_info()
    for port in ports:
        in_counter = chain_counters(_get_port_chain_name(port, INGRESS_DIRECTION))
        out_counter = chain_counters(_get_port_chain_name(port, EGRESS_DIRECTION))
        spoof_counter = chain_counters(_get_port_chain_name(port, SPOOF_FILTER))
        cache[port] = SGPortData(
            in_drop_bytes=in_counter['drop_bytes'],
            in_drop_packets=in_counter['drop_pkts'],
            in_accept_bytes=in_counter['acc_bytes'],
            in_accept_packets=in_counter['acc_pkts'],
            out_drop_bytes=out_counter['drop_bytes'] + spoof_counter['drop_bytes'],
            out_drop_packets=out_counter['drop_pkts'] + spoof_counter['drop_pkts'],
            out_accept_bytes=out_counter['acc_bytes'],
            out_accept_packets=out_counter['acc_pkts'],
        )





