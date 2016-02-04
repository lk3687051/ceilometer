import subprocess
from eventlet import greenthread

INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
SG_CHAIN = 'sg-chain'
SPOOF_FILTER = 'spoof-filter'
CHAIN_PREFIX = 'neutron-openvswi-'
CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o',
                     SPOOF_FILTER: 's'}
MAX_CHAIN_LEN_NOWRAP = 28

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

class SGmetering(object):
    """Wrapper for iptables.

    See IptablesTable for some usage docs

    A number of chains are set up to begin with.

    First, neutron-filter-top. It's added at the top of FORWARD and OUTPUT.
    Its name is not wrapped, so it's shared between the various neutron
    workers. It's intended for rules that need to live at the top of the
    FORWARD and OUTPUT chains. It's in both the ipv4 and ipv6 set of tables.

    For ipv4 and ipv6, the built-in INPUT, OUTPUT, and FORWARD filter chains
    are wrapped, meaning that the "real" INPUT chain has a rule that jumps to
    the wrapped INPUT chain, etc. Additionally, there's a wrapped chain named
    "local" which is jumped to from neutron-filter-top.

    For ipv4, the built-in PREROUTING, OUTPUT, and POSTROUTING nat chains are
    wrapped in the same was as the built-in filter chains. Additionally,
    there's a snat chain that is applied after the POSTROUTING chain.

    """
    def __init__(self, port):
        self.chain_in = self._get_port_chain_name(port, INGRESS_DIRECTION)
        self.chain_out = self._get_port_chain_name(port, EGRESS_DIRECTION)
        self.chain_spoof = self._get_port_chain_name(port, SPOOF_FILTER)
        self.in_drop_bytes = 0
        self.in_drop_packets = 0
        self.in_accept_bytes = 0
        self.in_accept_packets = 0
        self.out_drop_bytes = 0
        self.out_drop_packets = 0
        self.out_accept_bytes = 0
        self.out_accept_packets = 0
        #self.get_traffic_counters(self.chain_in, zero=True)

        acc_accept = {'pkts': 0, 'bytes': 0}
        acc_drop = {'pkts': 0, 'bytes':0}

        acc_accept['pkts'], acc_accept['bytes'], acc_drop['pkts'], acc_drop['bytes'] \
                  = self._get_counters_by_chain(self.chain_in)
        self.in_drop_bytes += acc_drop['bytes']
        self.in_drop_packets += acc_drop['pkts']
        self.in_accept_bytes += acc_accept['bytes']
        self.in_accept_packets += acc_accept['pkts']

        acc_accept['pkts'], acc_accept['bytes'], acc_drop['pkts'], acc_drop['bytes'] \
                  = self._get_counters_by_chain(self.chain_spoof)
        self.in_drop_bytes += acc_drop['bytes']
        self.in_drop_packets += acc_drop['pkts']
        #self.in_accept_bytes += acc_accept['bytes']
        #self.in_accept_packets += acc_accept['pkts']

        acc_accept['pkts'], acc_accept['bytes'], acc_drop['pkts'], acc_drop['bytes'] \
                  = self._get_counters_by_chain(self.chain_out)
        self.out_drop_bytes = acc_drop['bytes']
        self.out_drop_packets = acc_drop['pkts']
        self.out_accept_bytes = acc_accept['bytes']
        self.out_accept_packets = acc_accept['pkts']

    def _get_port_chain_name(self, port, direction):
        return ('%s%s%s' % (CHAIN_PREFIX, CHAIN_NAME_PREFIX[direction], port))[:MAX_CHAIN_LEN_NOWRAP]

    #    I think here have some performance issue.
    #    When we have much china, it will exec iptable**** much time, I think it will be too bad.
    #    Need get a good idea for it.
    def _get_counters_by_chain(self, chain, zero=False):
        """Return the sum of the traffic counters of all rules of a chain."""
        acc_accept = {'pkts': 0, 'bytes': 0}
        acc_drop = {'pkts': 0, 'bytes':0}

        cmd = "iptables"
        args = ['sudo', cmd,  '-L', chain, '-n', '-v', '-x']
        if zero:
            args.append('-Z')

        current_table = execute(args)
        current_lines = current_table.split('\n')

        for line in current_lines[2:]:
            if not line:
                break
            data = line.split()
            if (len(data) < 2 or
                    not data[0].isdigit() or
                    not data[1].isdigit()):
                break
            if data[2] == 'RETURN':
                acc_accept['pkts'] += int(data[0])
                acc_accept['bytes'] += int(data[1])
            elif data[2] == 'DROP' or data[2] == 'neutron-openvswi-sg-fallback':
                acc_drop['pkts'] += int(data[0])
                acc_drop['bytes'] += int(data[1])
            else:
                pass

        return acc_accept['pkts'], acc_accept['bytes'], acc_drop['pkts'], acc_drop['bytes']





