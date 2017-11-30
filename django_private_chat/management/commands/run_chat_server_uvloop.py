import asyncio
import websockets
import uvloop

from django.conf import settings
from django.core.management.base import BaseCommand
# from django_private_chat import channels_uvloop as channels

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from django_private_chat import channels
from django_private_chat import handlers
from django_private_chat.utils import logger


class Command(BaseCommand):
    help = 'Starts message center chat engine'

    def handle(self, *args, **options):
        asyncio.ensure_future(
            websockets.serve(
                handlers.main_handler,
                settings.CHAT_WS_SERVER_HOST,
                settings.CHAT_WS_SERVER_PORT
            )
        )
        logger.info('Chat server started')

        asyncio.ensure_future(handlers.new_messages_handler(channels.new_messages))
        #asyncio.async(handlers.users_changed_handler(channels.users_changed))
        asyncio.ensure_future(handlers.gone_online_handler(channels.gone_online))
        asyncio.ensure_future(handlers.check_online_handler(channels.check_online))
        asyncio.ensure_future(handlers.gone_offline_handler(channels.gone_offline))
        asyncio.ensure_future(handlers.is_typing_handler(channels.is_typing))
        asyncio.ensure_future(handlers.read_message_handler(channels.read_unread))
        asyncio.ensure_future(handlers.unread_msg_count_handler(channels.unread_msg_count))
        loop = asyncio.get_event_loop()
        loop.run_forever()
