# Generated by Django 5.1.4 on 2025-03-17 05:42

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0027_remove_blogsetting_parameters'),
    ]

    operations = [
        migrations.CreateModel(
            name='SocialMedia',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('platform', models.CharField(choices=[('facebook', 'Facebook'), ('X', 'X'), ('instagram', 'Instagram'), ('linkedin', 'LinkedIn')], max_length=20)),
                ('title', models.CharField(max_length=255)),
                ('link', models.URLField(max_length=500)),
                ('publish_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='social_media_posts', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Social Media Post',
                'verbose_name_plural': 'Social Media Posts',
                'ordering': ['-publish_date'],
            },
        ),
    ]
