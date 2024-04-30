from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('auth/login/', views.new_login, name='login'),
    path('auth/refresh/', views.refresh_token, name='refresh_token'),
    path('auth/verify-password/', views.verify_password, name='verify_password'),
    path('auth/save-password/', views.save_password, name='save_password'),
    path('auth/send-mail/', views.send_password_reset_email, name='send_password_reset_email'),
    path('auth/reset-password/', views.reset_password, name='reset_password'),
    path('auth/create-user/', views.create_user, name='create_user'),
    path('auth/check-user-exists/', views.check_user_exists, name='check_user_exists'),

    path('user/userDetails/', views.user_details, name='user_details'),
    path('user/change-photo/', views.change_user_image, name='change_user_image'),
    path('user/change-data-admin/', views.change_user_data_admin, name='change_user_data_admin'),
    path('user/show-users/', views.show_users, name='show_user'),
    path('user/get_image/<int:user_id>/', views.get_user_image, name='get_user_image'),
    path('user/update/', views.update_data_user, name='update_data_user'),

    path('items/search/', views.search_items, name='search_items'),
    path('items/search/<idItem>/', views.obtain_item_data, name='obtain_item_data'),
    path('items/search-availables/', views.search_items_availables, name='search_items_availables'),
    
    path('logs/save/', views.save_logs, name='save_logs'),
    
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)