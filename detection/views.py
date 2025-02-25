import os
from django.shortcuts import render
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import render, redirect
from django.contrib import messages 
from django.core.files.storage import default_storage
from .models import AnalysisResult
from datetime import datetime
import requests
from reportlab.pdfgen import canvas
from io import BytesIO
from uuid import uuid4
import validators
import logging 
import facebook


logger = logging.getLogger(__name__)
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
        
        if any(social in url.lower() for social in ["facebook.com", "twitter.com"]):
            messages.warning(request, "L'analyse des réseaux sociaux est limitée.")
            return redirect('index')

        # Envoi de l'URL à l'API
        api_url = "https://api.sightengine.com/1.0/check.json"
        params = {
            'url': url,
            'models': 'nudity,wad,offensive',  # Modèles à utiliser
            'api_user': API_USER,  # Utilisation de la variable d'environnement
            'api_secret': API_SECRET  # Utilisation de la variable d'environnement
        }
        try:
           # response = requests.post(api_url, json={"url": url}, timeout=10)
            response = requests.get(api_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as e:
             logger.error(f"Erreur lors de l'appel à l'API Sightengine : {e}")
             messages.error(request, "Erreur lors de l'analyse")
             return render(request, 'detection/index.html', {'error': "Erreur lors de l'analyse"})
        
        is_malicious = (
            data.get('nudity', {}).get('raw', 0) > 0.5 or
            data.get('weapon', 0) > 0.5 or
            data.get('alcohol', 0) > 0.5 or
            data.get('offensive', {}).get('prob', 0) > 0.5
        )

        if url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            content_type = 'image'
        elif url.lower().endswith(('.mp4', '.avi', '.mov')):
            content_type = 'video'
        else:
            content_type = 'unknown'
        


        buffer = BytesIO()
        p = canvas.Canvas(buffer)
        p.drawString(100, 750, f"Rapport d'analyse pour {url}")
        p.drawString(100, 730, f"Type de contenu: {content_type}")
        p.drawString(100, 710, f"Résultat: {'Malveillant' if data['is_malicious'] else 'Bénin'}")
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



def get_facebook_posts(request):
    try:
        # Récupérer le token
        access_token = os.getenv("FB_ACCESS_TOKEN")
        if not access_token:
            return render(request, 'error.html', {'message': 'FB_ACCESS_TOKEN manquant dans .env.'})

        # Récupérer les posts
        graph = facebook.GraphAPI(access_token)
        posts = graph.get_object('me/posts', fields='message,created_time')
        return render(request, 'detection/facebook_posts.html', {'posts': posts.get('data', [])})

    except facebook.GraphAPIError as e:
        return render(request, 'error.html', {'message': f'Erreur Facebook : {str(e)}'})
    except Exception as e:
        return render(request, 'error.html', {'message': f'Erreur inattendue : {str(e)}'})
   

