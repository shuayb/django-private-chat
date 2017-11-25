#
from django.views import generic
from braces.views import LoginRequiredMixin

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
# from . import models
# from . import utils
from django_private_chat import models
from django_private_chat import utils
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q
from django.http import Http404


class DialogListView(LoginRequiredMixin, generic.ListView):
    template_name = 'django_private_chat/dialogs.html'
    model = models.Dialog
    ordering = 'modified'

    def get_queryset(self):
        dialogs = models.Dialog.objects.filter(Q(owner=self.request.user) | Q(opponent=self.request.user))
        return dialogs

    def get_context_data(self, **kwargs):
        context = super().get_context_data()
        if self.kwargs.get('username'):
            user = get_object_or_404(get_user_model(), username=self.kwargs.get('username'))

            if user == self.request.user:
                raise Http404

            dialog = utils.get_dialogs_with_user(self.request.user, user)
            if len(dialog) == 0:
                dialog = models.Dialog.objects.create(owner=self.request.user, opponent=user)
            else:
                try:
                    dialog = dialog[0]
                except IndexError:
                    context['active_dialog'] = None
                    return context

            context['active_dialog'] = dialog
            if dialog.messages.exists():
                context['chat_messages'] = dialog.messages.all().prefetch_related('sender')
            else:
                context['chat_messages'] = None
        else:
            try:
                context['active_dialog'] = self.object_list[0]
                if self.object_list[0].messages.exists():
                    context['chat_messages'] = self.object_list[0].messages.all().prefetch_related('sender')
                else:
                    context['chat_messages'] = None
            except IndexError:
                context['active_dialog'] = None
                return context
        if self.request.user == context['active_dialog'].owner:
            context['opponent_username'] = context['active_dialog'].opponent.username
            context['opponent'] = context['active_dialog'].opponent
        else:
            context['opponent_username'] = context['active_dialog'].owner.username
            context['opponent'] = context['active_dialog'].owner
        context['ws_server_path'] = '{}://{}:{}/'.format(
            settings.CHAT_WS_SERVER_PROTOCOL,
            settings.CHAT_WS_SERVER_HOST,
            settings.CHAT_WS_SERVER_PORT,
        )

        context['user'] = self.request.user
        return context
        #
