# Generated by Django 5.0.4 on 2024-04-25 17:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('biblioApp', '0003_userprofile_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='log',
            name='log_level',
            field=models.CharField(max_length=1000),
        ),
    ]
