from django.urls import path
from . import views

app_name = 'timer'
urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('timers/', views.timers, name='timers'),
    path('timers/new/', views.new_timer, name='new_timer'),
    path('timers/<int:req_pk>/reset/', views.reset_timer, name='reset_timer'),
    path('timers/<int:req_pk>/delete/', views.delete_timer, name='delete_timer'),
]