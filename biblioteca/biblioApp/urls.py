from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('auth/login/', views.new_login, name='login'),
    path('auth/refresh/', views.refresh_token, name='refresh_token'),
    path('auth/verify-password/', views.verify_password, name='verify_password'),
    path('auth/save-password/', views.save_password, name='save_password'),
    path('user/userDetails/', views.user_details, name='user_details'),
    path('user/change-photo/', views.change_user_image, name='change_user_image'),
    path('user/get_image/<int:user_id>/', views.get_user_image, name='get_user_image'),
    path('user/update/', views.update_data_user, name='update_data_user'),
    path('items/search/', views.search_items, name='search_items'),
    path('items/search/<idItem>/', views.obtain_item_data, name='obtain_item_data'),
    path('items/search-availables/', views.search_items_availables, name='search_items_availables'),
    path('logs/save/', views.save_logs, name='save_log'),
    
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)