# coding: utf-8
from allauth.socialaccount import providers
from allauth.socialaccount.models import SocialApp
from django.http import Http404
from django.views.generic.base import TemplateView
from django.utils.functional import cached_property


class ExternalAuthView(TemplateView):
    template_name = 'external_auth.html'

    @cached_property
    def enabled_providers(self):
        return {
            p.id: p for p in providers.registry.get_list()
            if self._provider_is_ready_to_use(p)
        }

    def get(self, request, *args, **kwargs):
        provider_id = kwargs['provider_id']

        if provider_id not in self.enabled_providers:
            raise Http404()

        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context['provider'] = self.enabled_providers[kwargs['provider_id']]

        return context

    def _provider_is_ready_to_use(self, provider):
        try:
            provider.get_app(self.request)
        except SocialApp.DoesNotExist:
            return False
        return True
