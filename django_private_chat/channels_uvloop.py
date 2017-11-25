import asyncio
import uvloop


def get_new_uvloop_queue():
    loop = uvloop.new_event_loop()
    return asyncio.Queue(loop=loop)


new_messages = get_new_uvloop_queue()
users_changed = get_new_uvloop_queue()
gone_online = get_new_uvloop_queue()
gone_offline = get_new_uvloop_queue()
check_online = get_new_uvloop_queue()
is_typing = get_new_uvloop_queue()
read_unread = get_new_uvloop_queue()
