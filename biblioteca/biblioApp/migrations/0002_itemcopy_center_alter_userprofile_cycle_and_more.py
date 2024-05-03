# Generated by Django 5.0.4 on 2024-05-02 17:34

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('biblioApp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='itemcopy',
            name='center',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='biblioApp.center', verbose_name='Centre'),
            preserve_default=False,
        ),
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