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