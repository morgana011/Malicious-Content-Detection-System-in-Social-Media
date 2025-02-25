from django.urls import path
from . import views  # Assurez-vous d'importer vos vues


urlpatterns = [
    # Exemple d'une route
    path('', views.index, name='index'),
    path('facebook-posts/', views.get_facebook_posts, name='facebook_posts'),
]