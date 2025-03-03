# Generated by Django 5.1.6 on 2025-03-02 11:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detection', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='analysisresult',
            name='risk_score',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='analysisresult',
            name='status',
            field=models.CharField(default='pending', max_length=50),
        ),
        migrations.AlterField(
            model_name='analysisresult',
            name='url',
            field=models.CharField(max_length=255, unique=True),
        ),
    ]
