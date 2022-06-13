# coding: utf-8
from django.urls import path

from .views import ExternalAuthView

urlpatterns = [
    path('<str:provider_id>/', ExternalAuthView.as_view(), name='external_auth')
]
