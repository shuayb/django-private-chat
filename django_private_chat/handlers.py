import asyncio
import json
import logging
import websockets
from django.contrib.auth import get_user_model
from . import models, router
from django.db.models import Q
from .utils import get_user_from_session, get_user_from_session_v2, get_dialogs_with_user, get_all_logged_in_users
from django.core.exceptions import ObjectDoesNotExist

logger = logging.getLogger('django-private-dialog')
ws_connections = {}

@asyncio.coroutine
def target_message(conn, payload):
    """
    Distibuted payload (message) to one connection
    :param conn: connection
    :param payload: payload(json dumpable)
    :return:
    """
    try:
        yield from conn.send(json.dumps(payload))
    except Exception as e:
        logger.debug('could not send', e)


@asyncio.coroutine
def fanout_message(connections, payload):
    """
    Distributes payload (message) to all connected ws clients
    """
    for conn in connections:
        try:
            yield from conn.send(json.dumps(payload))
        except Exception as e:
            logger.debug('could not send', e)


@asyncio.coroutine
def gone_online_handler(stream):
    """
    Distributes the users online status to everyone he has dialog with
    """
    while True:
        packet = yield from stream.get()
        session_id = packet.get('session_key')
        if session_id:
            user_owner = get_user_from_session_v2(session_id)
            if user_owner:
                logger.debug('User ' + user_owner.username + ' gone online')

                # list all dialogs where user_own can chat
                usernames = list()
                dialogs = models.Dialog.objects.filter(Q(owner=user_owner) | Q(opponent=user_owner))
                for dialog in dialogs:
                    usernames.append(dialog.owner.username)
                    usernames.append(dialog.opponent.username)
                # remove duplicates
                usernames = list(set(usernames))
                # remove user_owner, user_owner is obviously online
                usernames.remove(user_owner.username)

                # sessions and usernames
                # logged_in_users = get_all_logged_in_users()
                # make sure UserSessions are cleaned properly.
                user_sessions = models.UserSession.objects.filter(user__username__in=usernames)

                # find opponents
                online_opponents = list()
                for session in user_sessions:
                    if list(filter(lambda x: x[0] == session.session.session_key, ws_connections)).__len__() > 0:
                        for pp in list(filter(lambda x: x[0] == session.session.session_key, ws_connections)):
                            online_opponents.append((session.user.username,pp[0],ws_connections[pp]))

                online_opponents_sockets = [i[2] for i in online_opponents]
                yield from fanout_message(online_opponents_sockets,
                                          {'type': 'gone-online', 'usernames': [user_owner.username]})
            else:
                pass  # invalid session id
        else:
            pass  # no session id


@asyncio.coroutine
def check_online_handler(stream):
    """
    Used to check user's online opponents and show their online/offline status on page on init
    """
    while True:
        packet = yield from stream.get()
        session_id = packet.get('session_key')
        opponent_username = packet.get('username')
        if session_id and opponent_username:
            user_owner = get_user_from_session_v2(session_id)
            if user_owner:
                # list all dialogs where user_own can chat
                usernames = list()
                dialogs = models.Dialog.objects.filter(Q(owner=user_owner) | Q(opponent=user_owner))
                for dialog in dialogs:
                    usernames.append(dialog.owner.username)
                    usernames.append(dialog.opponent.username)
                # remove duplicates
                usernames = list(set(usernames))
                # remove user_owner, user_owner is obviously online
                usernames.remove(user_owner.username)

                # sessions and usernames
                # logged_in_users = get_all_logged_in_users()
                # make sure UserSessions are cleaned properly.
                user_sessions = models.UserSession.objects.filter(user__username__in=usernames)

                # find currently online opponents usernames.
                online_opponents_usernames = list()
                for session in user_sessions:
                    if list(filter(lambda x: x[0] == session.session.session_key, ws_connections)).__len__() > 0:
                        for pp in list(filter(lambda x: x[0] == session.session.session_key, ws_connections)):
                            if session.user.username not in online_opponents_usernames:
                                online_opponents_usernames.append(session.user.username)

                user_window_connections = list()
                for x in ws_connections.items():
                    try:
                        if get_user_from_session_v2(x[0][0]).username == user_owner.username:
                            user_window_connections.append(x[1])
                    except ObjectDoesNotExist:
                        pass

                yield from fanout_message(user_window_connections,
                                          {'type': 'gone-online', 'usernames': online_opponents_usernames})

            else:
                pass  # invalid session id
        else:
            pass  # no session id or opponent username


@asyncio.coroutine
def gone_offline_handler(stream):
    """
    Distributes the users offline status to everyone he has dialog with
    """
    while True:
        packet = yield from stream.get()
        session_id = packet.get('session_key')
        if session_id:
            user_owner = get_user_from_session_v2(session_id)
            if user_owner:
                # After socket is deleted from ws_connection
                count = 0
                for x in ws_connections.items():
                    try:
                        if get_user_from_session_v2(x[0][0]).username == user_owner.username:
                            count = count + 1
                    except ObjectDoesNotExist:
                        pass

                if count < 1:
                    logger.debug('User ' + user_owner.username + ' gone offline')
                    # list all dialogs where user_own can chat
                    usernames = list()
                    dialogs = models.Dialog.objects.filter(Q(owner=user_owner) | Q(opponent=user_owner))
                    for dialog in dialogs:
                        usernames.append(dialog.owner.username)
                        usernames.append(dialog.opponent.username)
                    # remove duplicates
                    usernames = list(set(usernames))
                    # remove user_owner, user_owner is obviously online
                    usernames.remove(user_owner.username)

                    # sessions and usernames
                    # logged_in_users = get_all_logged_in_users()
                    # make sure UserSessions are cleaned properly.
                    user_sessions = models.UserSession.objects.filter(user__username__in=usernames)

                    # find opponents
                    online_opponents = list()
                    for session in user_sessions:
                        if list(filter(lambda x: x[0] == session.session.session_key, ws_connections)).__len__() > 0:
                            for pp in list(filter(lambda x: x[0] == session.session.session_key, ws_connections)):
                                online_opponents.append((session.user.username,pp[0],ws_connections[pp]))

                    online_opponents_sockets = [i[2] for i in online_opponents]
                    yield from fanout_message(online_opponents_sockets,
                                              {'type': 'gone-offline', 'usernames': [user_owner.username]})
            else:
                pass  # invalid session id
        else:
            pass  # no session id


@asyncio.coroutine
def new_messages_handler(stream):
    """
    Saves a new chat message to db and distributes msg to connected users
    """
    # TODO: handle no user found exception
    while True:
        packet = yield from stream.get()
        session_id = packet.get('session_key')
        msg = packet.get('message')
        username_opponent = packet.get('username')
        if session_id and msg and username_opponent:
            user_owner = get_user_from_session_v2(session_id)
            if user_owner:
                user_opponent = get_user_model().objects.get(username=username_opponent)
                dialog = get_dialogs_with_user(user_owner, user_opponent)
                if len(dialog) > 0:
                    # Save the message
                    msg = models.Message.objects.create(
                        dialog=dialog[0],
                        sender=user_owner,
                        text=packet['message'],
                        read=False
                    )
                    packet['created'] = msg.get_formatted_create_datetime()
                    packet['sender_name'] = msg.sender.username
                    packet['message_id'] = msg.id

                    try:
                        del packet['session_key']
                    except KeyError:
                        pass

                    logger.debug('created packet to send:' + str(packet))

                    connections = []

                    # In case same dialog is opened at multiple places by same person
                    for x in ws_connections.items():
                        if get_user_from_session_v2(x[0][0]).username == user_owner.username:
                            connections.append(x[1])

                        if get_user_from_session_v2(x[0][0]).username == user_opponent.username:
                            connections.append(x[1])

                    yield from fanout_message(connections, packet)
                else:
                    pass  # no dialog found
            else:
                pass  # no user_owner
        else:
            pass  # missing one of params


# Unused
# @asyncio.coroutine
# def users_changed_handler(stream):
#     pass
#     """
#     Sends connected client list of currently active users in the chatroom
#     """
#     while True:
#         yield from stream.get()
#
#         # Get list list of current active users
#         users = [
#             {'username': username, 'uuid': uuid_str}
#             for username, uuid_str in ws_connections.values()
#         ]
#
#         # Make packet with list of new users (sorted by username)
#         packet = {
#             'type': 'users-changed',
#             'value': sorted(users, key=lambda i: i['username'])
#         }
#         logger.debug(packet)
#         yield from fanout_message(ws_connections.keys(), packet)


# Todo Fix it.
# @asyncio.coroutine
# def is_typing_handler(stream):
#     pass
#     """
#     Show message to opponent if user is typing message
#     """
#     while True:
#         packet = yield from stream.get()
#         session_id = packet.get('session_key')
#         user_opponent = packet.get('username')
#         typing = packet.get('typing')
#         if session_id and user_opponent and typing is not None:
#             user_owner = get_user_from_session_v2(session_id)
#             if user_owner:
#                 opponent_socket = ws_connections.get((user_opponent, user_owner.username))
#                 if typing and opponent_socket:
#                     yield from target_message(opponent_socket,
#                                               {'type': 'opponent-typing', 'username': user_opponent})
#             else:
#                 pass  # invalid session id
#         else:
#             pass  # no session id or user_opponent or typing


@asyncio.coroutine
def read_message_handler(stream):
    """
    Send message to user if the opponent has read the message
    """
    while True:
        packet = yield from stream.get()
        session_id = packet.get('session_key')
        user_opponent = packet.get('username')
        message_id = packet.get('message_id')
        if session_id and user_opponent and message_id is not None:
            user_owner = get_user_from_session_v2(session_id)
            if user_owner:
                message = models.Message.objects.filter(id=message_id).first()
                if message:
                    message.read = True
                    message.save()
                    logger.debug('Message ' + str(message_id) + ' is now read')
                    # opponent_socket = ws_connections.get((user_opponent, user_owner.username))

                    connections = []
                    for x in ws_connections.items():
                        try:
                            if get_user_from_session_v2(x[0][0]).username == user_opponent:
                                connections.append(x[1])
                        except ObjectDoesNotExist:
                            pass

                    yield from fanout_message(connections,
                                                  {'type': 'opponent-read-message',
                                                   'username': user_opponent, 'message_id': message_id})
                else:
                    pass  # message not found
            else:
                pass  # invalid session id
        else:
            pass  # no session id or user_opponent or typing


@asyncio.coroutine
def main_handler(websocket, path):
    """
    An Asyncio Task is created for every new websocket client connection
    that is established. This coroutine listens to messages from the connected
    client and routes the message to the proper queue.
    This coroutine can be thought of as a producer.
    """

    # Get users name from the path
    path = path.split('/')
    session_id = path[1]
    dialog_id = path[2]
    username = path[3]
    user_owner = get_user_from_session_v2(session_id)
    if user_owner:
        #user_owner = user_owner.username
        # Persist users connection, associate user w/a unique ID
        #ws_connections[(user_owner, username)] = websocket
        #logger.debug("---------------\n ws connections \n" + str(ws_connections) + "\n---------------")
        # Persist users connection, associate session_id (owner), current_window (owner's current window), username (opponent)
        ws_connections[(session_id, dialog_id, username)] = websocket
        #logger.debug("---------------\n added ws connections:\n" + "SesionID: " + str(session_id) + "|" + str(dialog_id) + "|" + str(username) + "|" +  str(ws_connections[(session_id, dialog_id, username)]) + "\n---------------")

        # While the websocket is open, listen for incoming messages/events
        # if unable to listening for messages/events, then disconnect the client
        try:
            while websocket.open:
                data = yield from websocket.recv()
                if not data: continue
                logger.debug(data)
                try:
                    yield from router.MessageRouter(data)()
                except Exception as e:
                    logger.error('could not route msg', e)

        except websockets.exceptions.InvalidState:  # User disconnected
            pass
        finally:
            #del ws_connections[(user_owner, username)]
            logger.debug("deleted" + str(ws_connections[(session_id, dialog_id, username)]))
            del ws_connections[(session_id, dialog_id, username)]
    else:
        logger.info("Got invalid session_id attempt to connect " + session_id)
