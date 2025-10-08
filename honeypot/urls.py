"""
URL configuration for honeyport project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin', admin.site.urls),
    path('',views.dashboard,name="dashboard"),
    path('login', views.handlelogin, name='handlelogin'),
    path('logout', views.handlelogout, name='handlelogout'),
    path('dashboard',views.dashboard,name="dashboard"),
    path('network',views.network,name="network"),
    path('setup',views.setup,name="setup"),
    path('server-setup',views.server_setup,name="server_setup"),
    path('start-flask-server', views.start_flask_server, name='start-flask-server'),
    path('stop-flask-server', views.stop_flask_server, name='stop-flask-server'),
    path('start-network-server', views.start_network_server, name='start_network_server'),
    path('stop-network-server', views.stop_network_server, name='stop_network_server'),
    path('network-setup', views.network_setup, name='network_setup'),
    path('Keylogger',views.Keylogger,name="Keylogger"),
    path('website',views.website,name="website"),
    # ... all your other urls
    path('api/attack-data/', views.attack_type_data, name='attack-data-api'),
    
    # ADD THIS NEW LINE
    path('api/get-new-attacks/', views.get_new_attacks_api, name='get-new-attacks-api'),

    # URL for our new chart data API
    path('api/attack-data/', views.attack_type_data, name='attack-data-api'),
]