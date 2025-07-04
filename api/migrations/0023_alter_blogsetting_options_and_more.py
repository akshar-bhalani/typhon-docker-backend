# Generated by Django 5.1.4 on 2025-02-11 05:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0022_subscriptionplan_product_id'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='blogsetting',
            options={'ordering': ['id']},
        ),
        migrations.AlterModelOptions(
            name='subscriptionplan',
            options={'ordering': ['id']},
        ),
        migrations.AlterModelOptions(
            name='user',
            options={'ordering': ['id']},
        ),
        migrations.AlterModelOptions(
            name='wordpress',
            options={'ordering': ['id']},
        ),
        migrations.AddField(
            model_name='user',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
    ]
