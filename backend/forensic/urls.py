from django.urls import include, path, re_path

from api.views import frontend

urlpatterns = [
    path("api/", include("api.urls")),
    re_path(r"^assets/(?P<path>.*)$", frontend.asset),
    re_path(r"^(?P<path>(?!api/).*)$", frontend.index),
]
