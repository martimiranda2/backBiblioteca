from django.contrib import admin
from .models import *

admin.site.register(Role)
admin.site.register(UserProfile)
admin.site.register(Reservation)
admin.site.register(Loan)
admin.site.register(Request)
admin.site.register(ItemCopy)
admin.site.register(Book)
admin.site.register(CD)

class LogAdmin(admin.ModelAdmin):
    list_display = ('title', 'log_level', 'description', 'user', 'date', 'route')  # campos que se mostrarán en la lista
    list_filter = ('log_level', 'user', 'date')  # campos por los que se podrá filtrar
    search_fields = ('title', 'description')  # campos que se podrán usar para la búsqueda

admin.site.register(Log, LogAdmin)