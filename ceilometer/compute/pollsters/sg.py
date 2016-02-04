# Copyright 2012 Red Hat, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import copy

from oslo_log import log
import ceilometer
from ceilometer.compute import pollsters
from ceilometer.compute.pollsters import util
from ceilometer.i18n import _, _LW
from ceilometer import sample
from ceilometer.compute import sg_meter
from oslo_utils import timeutils
from ceilometer.agent import plugin_base
import collections

LOG = log.getLogger(__name__)
class _Base(plugin_base.PollsterBase):

    @property
    def default_discovery(self):
        return 'local_ports'

    @staticmethod
    def make_sg_sample(port, name, type, unit, volume):
        return sample.Sample(
            name=name,
            type=type,
            unit=unit,
            volume=volume,
            user_id=port['network_id'],
            project_id=port['tenant_id'],
            resource_id=port['device_id'],
            timestamp=timeutils.utcnow().isoformat(),
            resource_metadata=None,
        )

    def _record_poll_time(self):
        """Method records current time as the poll time.

        :return: time in seconds since the last poll time was recorded
        """
        current_time = timeutils.utcnow()
        duration = None
        if hasattr(self, '_last_poll_time'):
            duration = timeutils.delta_seconds(self._last_poll_time,
                                               current_time)
        self._last_poll_time = current_time
        return duration

    def get_samples(self, manager, cache, resources):
        i_cache = cache.setdefault("sgstats", {})
        if len(i_cache) is 0:
            sg_meter.get_sg_cache(self, resources, cache)

        self._inspection_duration = self._record_poll_time()
        for port in resources:
            LOG.debug('checking net info for instance %s', port['id'])
            try:
                c_data = i_cache[port['id']]
                yield self._get_sample(port, c_data)
            except Exception as err:
                LOG.exception(_('Ignoring port %(port_id)s: %(error)s'),
                              {'port_id': port['id'], 'error': err})

class IncomingAcceptBytesPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.incoming.accept.bytes',
            type=sample.TYPE_GAUGE,
            unit='B',
            volume=info.in_accept_bytes,
        )

class IncomingAcceptPktsPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.incoming.accept.pkts',
            type=sample.TYPE_GAUGE,
            unit='pkt',
            volume=info.in_accept_packets,
        )

class IncomingDropBytesPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.incoming.drop.bytes',
            type=sample.TYPE_GAUGE,
            unit='B',
            volume=info.in_drop_bytes,
        )

class IncomingDropPktsPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.incoming.drop.pkts',
            type=sample.TYPE_GAUGE,
            unit='pkt',
            volume=info.in_drop_packets,
        )

class OutgoingAcceptBytesPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.outgoing.accept.bytes',
            type=sample.TYPE_GAUGE,
            unit='B',
            volume=info.out_accept_bytes,
        )

class OutgoingAcceptPktsPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.outgoing.accept.pkts',
            type=sample.TYPE_GAUGE,
            unit='pkt',
            volume=info.out_accept_packets,
        )

class OutgoingDropBytesPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.outgoing.drop.bytes',
            type=sample.TYPE_GAUGE,
            unit='B',
            volume=info.out_drop_bytes,
        )

class OutgoingDropPktsPollster(_Base):
    def _get_sample(self, port, info):
        return self.make_sg_sample(
            port,
            name='sg.outgoing.drop.pkts',
            type=sample.TYPE_GAUGE,
            unit='pkt',
            volume=info.out_drop_packets,
        )
