from django.urls import path
from . import views  # Assurez-vous d'importer vos vues


urlpatterns = [
    # Exemple d'une route
    path('', views.index, name='index'),
    path('facebook-posts/', views.get_facebook_post_content, name='facebook_post_content'),
    path('result/<int:result_id>/', views.result, name='result'),

]