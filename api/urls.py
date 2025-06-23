from django.urls import path
from .views import (
    SignupView, 
    LoginView, 
    LogoutView,
    StripeWebhookView, 
    UserProfileView
)

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('stripe/webhook/', StripeWebhookView.as_view(), name='stripe-webhook'),
]