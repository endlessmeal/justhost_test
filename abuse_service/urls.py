from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('domains/', views.domains),
    path('abuses/', views.abuses)
]
