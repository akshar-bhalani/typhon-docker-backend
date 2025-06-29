# Generated by Django 5.1.4 on 2025-01-24 05:45

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_alter_user_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='assigned_admin',
            field=models.ForeignKey(blank=True, limit_choices_to={'role': 'Admin'}, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
        ),
    ]
