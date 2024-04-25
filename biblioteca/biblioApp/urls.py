from django.urls import path
from . import views

urlpatterns = [
    path('auth/login/', views.new_login, name='login'),
    path('auth/refresh/', views.refresh_token, name='refresh_token'),
    path('auth/verify-password/', views.verify_password, name='verify_password'),
    path('auth/save-password/', views.save_password, name='save_password'),
    path('user/userDetails/', views.user_details, name='user_details'),
    path('user/update/', views.update_data_user, name='update_data_user'),
    path('items/search/', views.search_items, name='search_items'),
    path('logs/save/', views.save_logs, name='save_log'),
]