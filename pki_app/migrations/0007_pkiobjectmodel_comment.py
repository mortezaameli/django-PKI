# Generated by Django 2.2 on 2020-10-12 15:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki_app', '0006_auto_20201010_2355'),
    ]

    operations = [
        migrations.AddField(
            model_name='pkiobjectmodel',
            name='comment',
            field=models.TextField(blank=True, default=''),
        ),
    ]
