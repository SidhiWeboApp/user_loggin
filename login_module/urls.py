from django.urls import path, re_path
from .views import *

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('request-reset-email/', request_reset_email, name = 'request-reset-email'),
    re_path(r"^reset-password/(?P<uid>[-\w]+)_(?P<token>[-\w]+)/$", resetPassword, name="reset-password")
]