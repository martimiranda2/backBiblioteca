# Generated by Django 5.0.4 on 2024-04-23 09:42

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('biblioApp', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='request',
            options={'verbose_name': 'Peticions', 'verbose_name_plural': 'Petició'},
        ),
        migrations.AlterModelOptions(
            name='userprofile',
            options={'verbose_name': "Perfil d'usuari", 'verbose_name_plural': "Perfils d'usuari"},
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='email',
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='dni',
            field=models.CharField(blank=True, max_length=9, null=True, unique=True, verbose_name='DNI'),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Usuari'),
        ),
    ]