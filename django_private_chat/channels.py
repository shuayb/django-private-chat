import asyncio

new_messages = asyncio.Queue()
users_changed = asyncio.Queue()
gone_online = asyncio.Queue()
gone_offline = asyncio.Queue()
check_online = asyncio.Queue()
is_typing = asyncio.Queue()
read_unread = asyncio.Queue()
unread_msg_count = asyncio.Queue()
