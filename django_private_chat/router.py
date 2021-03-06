import asyncio
import json
import logging

from .channels import new_messages, users_changed, gone_offline, gone_online, check_online, is_typing, read_unread, unread_msg_count

logger = logging.getLogger('django-private-dialog')


class MessageRouter(object):
    MESSAGE_QUEUES = {
        'new-message': new_messages,
        'new-user': users_changed,
        'gone-online': gone_online,
        'gone-offline': gone_offline,
        'check-online': check_online,
        'is-typing': is_typing,
        'read-message': read_unread,
        'unread-msg-count': unread_msg_count
    }

    def __init__(self, data):
        try:
            self.packet = json.loads(data)
        except Exception as e:
            logger.debug('could not load json: {}'.format(str(e)))

    def get_packet_type(self):
        return self.packet['type']

    @asyncio.coroutine
    def __call__(self):
        logger.debug('routing message: {}'.format(self.packet))
        send_queue = self.get_send_queue()
        yield from send_queue.put(self.packet)

    def get_send_queue(self):
        return self.MESSAGE_QUEUES[self.get_packet_type()]
