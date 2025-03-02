from django.db import models
import os
from uuid import uuid4  


def upload_to_reports(instance, filename):
    ext = filename.split('.')[-1]
    new_filename = f"{uuid4()}.{ext}"  
    return os.path.join('reports', new_filename)

class AnalysisResult(models.Model):
    url = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=50, default="pending")
    risk_score = models.IntegerField(null=True, blank=True)
    

    CONTENT_TYPE=[
        ('image', 'Image'),
        ('video', 'Vidéo'),
        ('document', 'Document'),
        ('other', 'Autre'),

    ]
    content_type = models.CharField(max_length=50, choices= CONTENT_TYPE, default='other') 
    is_malicious = models.BooleanField(default=False, help_text="Score de confiance de l'analyse (0 à 1)")  
    analysis_report = models.FileField(upload_to=upload_to_reports)  
    created_at = models.DateTimeField(auto_now_add=True) 

    def __str__(self):
        return f"Analysis of {self.url} at {self.created_at}"




