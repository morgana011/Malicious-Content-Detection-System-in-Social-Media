import os
import requests
import logging
import validators
import facebook
import json
from io import BytesIO
from uuid import uuid4
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.core.files.storage import default_storage
from reportlab.pdfgen import canvas
from .models import AnalysisResult
from django.http import Http404

# Configuration du logger
logger = logging.getLogger(__name__)

# Récupération des clés API depuis les variables d'environnement
API_USER = os.getenv("SIGHTENGINE_API_USER")
API_SECRET = os.getenv("SIGHTENGINE_API_SECRET")

def analyze_image_url(image_url):
    """
    Analyse une image en utilisant l'API Sightengine en soumettant son URL.
    """
    api_url = "https://api.sightengine.com/1.0/check.json"
    params = {
        'url': image_url,
        'models': 'nudity-2.1,weapon,alcohol,recreational_drug,medical,offensive-2.0,gore-2.0,tobacco,violence,self-harm,gambling',
        'api_user': API_USER,
        'api_secret': API_SECRET
    }

    try:
        response = requests.get(api_url, params=params, timeout=10)
        response.raise_for_status()  # Lève une erreur pour les codes de statut incorrects
        data = response.json()
        logger.info(f"Réponse de l'API Sightengine : {data}")
        return data
    except requests.RequestException as e:
        logger.error(f"Erreur lors de l'appel à l'API Sightengine : {e}")
        return None

def analyze_image_upload(image_file):
    """
    Analyse une image en utilisant l'API Sightengine par téléchargement direct.
    """
    api_url = "https://api.sightengine.com/1.0/check.json"
    params = {
        'models': 'nudity-2.1,weapon,alcohol,recreational_drug,medical,offensive-2.0,gore-2.0,tobacco,violence,self-harm,gambling',
        'api_user': API_USER,
        'api_secret': API_SECRET
    }
    files = {'media': image_file}

    try:
        response = requests.post(api_url, files=files, data=params, timeout=10)
        response.raise_for_status()  # Lève une erreur pour les codes de statut incorrects
        data = response.json()
        logger.info(f"Réponse de l'API Sightengine : {data}")
        return data
    except requests.RequestException as e:
        logger.error(f"Erreur lors de l'appel à l'API Sightengine : {e}")
        return None

def is_content_malicious(analysis_result):
    """
    Détermine si le contenu est malveillant en fonction des résultats de l'analyse.
    """
    return (
        analysis_result.get('nudity', {}).get('raw', 0) > 0.5 or
        analysis_result.get('weapon', {}).get('prob', 0) > 0.5 or
        analysis_result.get('gore', {}).get('prob', 0) > 0.5 or
        analysis_result.get('violence', {}).get('prob', 0) > 0.5 or
        analysis_result.get('self-harm', {}).get('prob', 0) > 0.5 or
        analysis_result.get('gambling', {}).get('prob', 0) > 0.5
    )

def generate_pdf_report(analysis_result, url, content_type):
    """
    Génère un rapport PDF avec les résultats de l'analyse.
    """
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.drawString(100, 750, f"Rapport d'analyse pour {url}")
    p.drawString(100, 730, f"Type de contenu: {content_type}")
    p.drawString(100, 710, f"Résultat: {'Malveillant' if is_content_malicious(analysis_result) else 'Bénin'}")
    p.drawString(100, 690, f"Détails: {json.dumps(analysis_result, indent=2)}")
    p.showPage()
    p.save()

    buffer.seek(0)
    return buffer

def save_analysis_result(url, analysis_result, is_malicious, content_type):
    """
    Sauvegarde le résultat de l'analyse dans la base de données.
    Si l'URL existe déjà, met à jour l'enregistrement existant.
    """
    result, created = AnalysisResult.objects.update_or_create(
        url=url,
        defaults={
            "status": "Analyzed",
            "risk_score": 100 if is_malicious else 0,
            "content_type": content_type,
            "is_malicious": is_malicious,
            "details": json.dumps(analysis_result)
        }
    )
    return result

def get_facebook_post_content(post_id):
    """
    Récupère l'URL directe de l'image ou de la vidéo d'un post Facebook via l'API Graph.
    """
    access_token = os.getenv("FB_ACCESS_TOKEN")
    
    if not access_token:
        logger.error("FB_ACCESS_TOKEN manquant")
        return {"error": "FB_ACCESS_TOKEN manquant"}
    
    try:
        # Initialiser l'API Graph avec le token d'accès
        graph = facebook.GraphAPI(access_token)
        
        # Demander les champs pertinents pour le type de contenu
        post_data = graph.get_object(post_id, fields="images,picture,source")
        
        # Initialisation des variables pour stocker les URLs
        image_urls = []
        video_url = None

        # Vérification de la présence de 'images' (pour les posts avec des images)
        if "images" in post_data:
            for image in post_data["images"]:
                image_url = image.get("source")  # 'source' contient l'URL de l'image en haute résolution
                if image_url:
                    image_urls.append(image_url)

        # Vérification de la présence de 'source' (pour les vidéos)
        if "source" in post_data:
            video_url = post_data["source"]

        # Si aucune image ou vidéo n'est trouvée, loguer un message d'information
        if not image_urls and not video_url:
            logger.info(f"Le post {post_id} ne contient ni image ni vidéo.")
        
        return {
            "image_urls": image_urls,
            "video_url": video_url
        }

    except facebook.GraphAPIError as e:
        error_message = str(e)
        if "Unsupported get request" in error_message:
            logger.error("Accès refusé : le post est privé ou les permissions sont insuffisantes.")
            return {"error": "Accès refusé : le post est privé ou les permissions sont insuffisantes."}
        else:
            logger.exception(f"Erreur API Graph Facebook : {e}")
            return {"error": f"Erreur API Graph Facebook : {e}"}

def index(request):
    if request.method == "POST":
        url = request.POST.get("url", "")
        uploaded_file = request.FILES.get('image')

        if url:
            # Analyse par URL
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
            else:
                # Analyse d'une URL directe
                media_url = url
                content_type = "image"  # Par défaut, considérez-le comme une image

            analysis_result = analyze_image_url(media_url)
        elif uploaded_file:
            # Analyse par téléchargement direct
            analysis_result = analyze_image_upload(uploaded_file)
            content_type = "image"
        else:
            messages.error(request, "Aucune URL ou fichier fourni.")
            return redirect('index')

        if analysis_result:
            is_malicious = is_content_malicious(analysis_result)
            
            # Générer le rapport PDF
            pdf_buffer = generate_pdf_report(analysis_result, url or "Image téléchargée", content_type)
            
            # Sauvegarder les résultats dans la base de données
            result = AnalysisResult.objects.create(
                url=url or "",
                status="Analyzed",
                risk_score=100 if is_malicious else 0,
                content_type=content_type,
                is_malicious=is_malicious,
                details=json.dumps(analysis_result)
            )
            
            # Sauvegarder le fichier PDF
            pdf_name = f"reports/{uuid4()}.pdf"
            result.analysis_report.save(pdf_name, pdf_buffer)
            
            # Rediriger vers la page de résultat
            messages.success(request, "Analyse terminée avec succès.")
            return redirect('result', result_id=result.id)
        else:
            messages.error(request, "Erreur lors de l'analyse.")
            return redirect('index')

    return render(request, 'detection/index.html')
def result(request, result_id):
    try:
        result = get_object_or_404(AnalysisResult, id=result_id)
    except Http404:
        return render(request, 'detection/error.html', {'message': "Résultat introuvable"})
    
    return render(request, 'detection/result.html', {'result': result})