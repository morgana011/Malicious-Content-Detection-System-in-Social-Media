from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),  # Page d'accueil pour l'analyse
    path('result/<int:result_id>/', views.result, name='result'),  # Affichage des résultats
    path('analyze/', views.analyze_image_upload, name='analyze_image_upload'),  # Nouvelle route pour l'analyse par téléchargement
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)