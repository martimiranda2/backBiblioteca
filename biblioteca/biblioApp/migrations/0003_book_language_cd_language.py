# Generated by Django 5.0.4 on 2024-05-03 14:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('biblioApp', '0002_itemcopy_center_alter_userprofile_cycle_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='book',
            name='language',
            field=models.CharField(default='en', max_length=10, verbose_name='Idioma'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='cd',
            name='language',
            field=models.CharField(default='en', max_length=10, verbose_name='Idioma'),
            preserve_default=False,
        ),
    ]