# Generated by Django 5.0.4 on 2024-05-01 21:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('biblioApp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='cycle',
            field=models.CharField(blank=True, default='', max_length=100, null=True, verbose_name='Curs al que pertany'),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='date_of_birth',
            field=models.DateField(blank=True, null=True, verbose_name='Data de naixement'),
        ),
    ]
