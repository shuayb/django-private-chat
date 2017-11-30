# -*- coding: utf-8 -*-

from django.db import models
from model_utils.models import TimeStampedModel, SoftDeletableModel
from django.conf import settings
from django.template.defaultfilters import date as dj_date
from django.utils.translation import ugettext as _

class Dialog(TimeStampedModel):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_("Dialog owner"), related_name="selfDialogs")
    opponent = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_("Dialog opponent"))

    def is_last_read(self, user):
        return self.messages.filter(sender=user).last().read

    def __str__(self):
        return _("Chat with ") + self.opponent.username


class Message(TimeStampedModel, SoftDeletableModel):
    dialog = models.ForeignKey(Dialog, verbose_name=_("Dialog"), related_name="messages")
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_("Author"), related_name="messages")
    text = models.TextField(verbose_name=_("Message text"))
    read = models.BooleanField(verbose_name=_("Read"), default=False)
    all_objects = models.Manager()

    def get_formatted_create_datetime(self):
        return dj_date(self.created, settings.DATETIME_FORMAT)

    def get_create_datetime_isoformated(self):
        return self.created.isoformat()

    def __str__(self):
        return self.sender.username + "(" + self.get_create_datetime_isoformated() + ") - '" + self.text + "'"

    class Meta:
        ordering = ["created"]

# http://gavinballard.com/associating-django-users-sessions/
from django.contrib.sessions.models import Session
class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    session = models.ForeignKey(Session)

from django.contrib.auth.signals import user_logged_in

def user_logged_in_handler(sender, request, user, **kwargs):
    UserSession.objects.get_or_create(
        user = user,
        session_id = request.session.session_key
    )

user_logged_in.connect(user_logged_in_handler)

# That’s really all we need to do to keep the user associated with their sessions.
# Now, we can implement delete_user_sessions() like this:


def delete_user_sessions(user):
    user_sessions = UserSession.objects.filter(user=user)
    for user_session in user_sessions:
        user_session.session.delete()

# Because of the way Django’s ForeignKey relations work on deletion,
# calling user_session.session.delete() will also remove the associated UserSession object.
# This will also be the case if you’re cleaning up expired sessions through a cron job or similar.
