import os
import requests
import logging
import validators
import facebook
from io import BytesIO
from uuid import uuid4
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.core.files.storage import default_storage
from reportlab.pdfgen import canvas
from .models import AnalysisResult

# Configuration du logger
logger = logging.getLogger(__name__)

# Récupération des clés API depuis les variables d'environnement
API_USER = os.getenv("SIGHTENGINE_API_USER")
API_SECRET = os.getenv("SIGHTENGINE_API_SECRET")

def index(request):
    status = ""
    risk_score = 0  # Définir une valeur de score de risque par défaut

    if request.method == "POST":
        url = request.POST.get("url", "")
        
        if not validators.url(url):
            logger.warning(f"URL invalide soumise : {url}")
            messages.error(request, 'URL invalide')
            return render(request, 'detection/index.html', {'error': 'URL invalide'})

        # Vérification du type de contenu
        if 'facebook.com' in url.lower():
            # Extraire l'ID du post Facebook
            post_id = url.split("fbid=")[-1].split("&")[0] if "fbid=" in url else None

            if not post_id:
                messages.error(request, "URL Facebook invalide ou post non détecté.")
                return redirect('index')

            # Récupérer le contenu du post Facebook
            facebook_content = get_facebook_post_content(post_id)

            if not facebook_content:
                messages.error(request, "Impossible d'obtenir les données du post Facebook.")
                return redirect('index')

            text_content = facebook_content.get("text")
            image_url = facebook_content.get("image_urls")[0] if facebook_content.get("image_urls") else None
            video_url = facebook_content.get("video_url")

            # Déterminer le type de contenu
            if image_url:
                media_url = image_url
                content_type = "image"
            elif video_url:
                media_url = video_url
                content_type = "video"
            else:
                messages.warning(request, "Ce post ne contient ni image ni vidéo.")
                return redirect('index')

            # Envoyer l'URL de l'image/vidéo à Sightengine pour analyse
            api_url = "https://api.sightengine.com/1.0/check.json"
            params = {
                'url': media_url,
                'models': 'nudity,weapon,alcohol,offensive',
                'api_user': API_USER,
                'api_secret': API_SECRET
            }
            try:
                response = requests.get(api_url, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()
                logger.info(f"Réponse de Sightengine : {data}")
            except (requests.RequestException, ValueError) as e:
                logger.error(f"Erreur lors de l'appel à Sightengine : {e}")
                messages.error(request, "Erreur lors de l'analyse")
                return render(request, 'detection/index.html', {'error': "Erreur lors de l'analyse"})

            # Détection du contenu malveillant
            is_malicious = (
                data.get('nudity', {}).get('raw', 0) > 0.5 or
                data.get('weapon', {}).get('prob', 0) > 0.5 or
                data.get('alcohol', {}).get('prob', 0) > 0.5 or
                data.get('offensive', {}).get('prob', 0) > 0.5
            )

            # Génération d'un rapport PDF
            buffer = BytesIO()
            p = canvas.Canvas(buffer)
            p.drawString(100, 750, f"Rapport d'analyse pour {url}")
            p.drawString(100, 730, f"Type de contenu: {content_type}")
            p.drawString(100, 710, f"Résultat: {'Malveillant' if is_malicious else 'Bénin'}")
            p.showPage()
            p.save()

            # Sauvegarde du fichier PDF
            buffer.seek(0)
            pdf_name = f"reports/{uuid4()}.pdf"
            pdf_path = default_storage.save(pdf_name, buffer)

            # Sauvegarde en base de données
            result, created = AnalysisResult.objects.get_or_create(
                url=url,  # Remplace 'url' par la variable contenant l'URL
                defaults={
                    "status": "URL analysée",
                    "risk_score": 100  # Calcul du score de risque à définir
                }
            )

            messages.success(request, 'Analyse terminée avec succès')

            return redirect('result', result_id=result.id)

    return render(request, 'detection/index.html')

def result(request, result_id):
    result = get_object_or_404(AnalysisResult, id=result_id)
    return render(request, 'detection/result.html', {'result': result})

def get_facebook_post_content(post_id):
    """
    Récupère uniquement l'image d'un post Facebook via l'API Graph.
    Retourne un dictionnaire avec les URLs des images ou une erreur.
    """
    access_token = os.getenv("FB_ACCESS_TOKEN")
    
    if not access_token:
        logger.error("FB_ACCESS_TOKEN manquant")
        return {"error": "FB_ACCESS_TOKEN manquant"}
    
    try:
        # Initialiser l'API Graph avec le token d'accès
        graph = facebook.GraphAPI(access_token)
        
        # Demander uniquement les champs pertinents pour le type de contenu
        post_data = graph.get_object(post_id, fields="images,picture")
        print(post_data)
        
        # Initialisation de la liste pour stocker les URLs des images
        image_urls = []

        # Vérification de la présence de 'images' (pour les posts avec des images)
        if "images" in post_data:
            for image in post_data["images"]:
                image_url = image.get("source")  # 'source' contient l'URL de l'image en haute résolution
                if image_url:
                    image_urls.append(image_url)

        if not image_urls and "picture" in post_data:
            image_urls.append(post_data["picture"])

        # Si aucune image n'est trouvée, loguer un message d'information
        if not image_urls:
            logger.info(f"Le post {post_id} ne contient pas d'image.")
        
        return {
            "image_urls": image_urls
        }

    except facebook.GraphAPIError as e:
        error_message = str(e)
        if "Unsupported get request" in error_message:
            logger.error("Accès refusé : le post est privé ou les permissions sont insuffisantes.")
            return {"error": "Accès refusé : le post est privé ou les permissions sont insuffisantes."}
        else:
            logger.exception(f"Erreur API Graph Facebook : {e}")
            return {"error": f"Erreur API Graph Facebook : {e}"}
