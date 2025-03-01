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
    if request.method == 'POST':
        url = request.POST.get('url')

        # Vérification de l'URL
        if not validators.url(url):
            logger.warning(f"URL invalide soumise : {url}")
            messages.error(request, 'URL invalide')
            return render(request, 'detection/index.html', {'error': 'URL invalide'})

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
            image_url = facebook_content.get("image_url")
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
                'models': 'nudity,wad,offensive',
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
            result = AnalysisResult.objects.create(
                url=url,
                content_type=content_type,
                is_malicious=is_malicious,
                analysis_report=pdf_path
            )

            messages.success(request, 'Analyse terminée avec succès')

            return redirect('result', result_id=result.id)

    return render(request, 'detection/index.html')

def result(request, result_id):
    result = get_object_or_404(AnalysisResult, id=result_id)
    return render(request, 'detection/result.html', {'result': result})

def get_facebook_post_content(post_id):
    """
    Récupère l'image, la vidéo et le texte d'un post Facebook via l'API Graph.
    Retourne un dictionnaire contenant les URLs des médias et le texte du post.
    """
    access_token = os.getenv("FB_ACCESS_TOKEN")
    logger.info(f"FB_ACCESS_TOKEN chargé : {access_token}")  # Ajoutez ce log
    if not access_token:
        logger.error("FB_ACCESS_TOKEN manquant")
        return None


    try:
        graph = facebook.GraphAPI(access_token)
        post_data = graph.get_object(post_id, fields="message,full_picture,attachments")

        # Récupérer le texte du post
        text_content = post_data.get("message", "")

        # Récupérer l'image si disponible
        image_url = post_data.get("full_picture")

        # Récupérer la vidéo si disponible
        video_url = None
        if "attachments" in post_data:
            attachments = post_data["attachments"].get("data", [])
            for attachment in attachments:
                if attachment.get("type") == "video":
                    video_url = attachment["url"]
                    break  # Prend la première vidéo trouvée

        return {"text": text_content, "image_url": image_url, "video_url": video_url}

    except facebook.GraphAPIError as e:
        logger.error(f"Erreur API Graph Facebook : {e}")
        return None
