# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-13 21:02
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('library', '0006_auto_20161107_2328'),
    ]

    operations = [
        migrations.CreateModel(
            name='FrontpageMessage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rank', models.IntegerField(db_index=True, default=0, help_text='Messages are ordered by rank when listed on the front page')),
                ('title', models.CharField(max_length=254)),
                ('body', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True, db_index=True)),
            ],
            options={
                'ordering': ['rank', '-updated_at'],
            },
        ),
    ]