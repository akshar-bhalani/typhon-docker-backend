
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User,Blog

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('email', 'name', 'role', 'status', 'is_staff', 'is_superuser', 'created_at')
    list_filter = ('role', 'status', 'is_staff', 'is_superuser')
    search_fields = ('email', 'name', 'company_name')
    ordering = ('-created_at',)
    
    # Exclude the created_at field from fieldsets

 
   
admin.site.register(Blog)
# Register the model with the custom admin class
admin.site.register(User, CustomUserAdmin)

