# Generated by Django 5.1.4 on 2025-02-18 05:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_wordpress_is_deleted'),
    ]

    operations = [
        migrations.AddField(
            model_name='blogsetting',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
    ]
