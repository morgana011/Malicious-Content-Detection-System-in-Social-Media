
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('detection/', include('detection.urls')),  # Assurez-vous que 'include' est importé
]

