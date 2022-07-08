# Generated by Django 2.2 on 2020-11-08 16:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki_app', '0011_pkiobjectmodel_category'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pkiobjectmodel',
            name='category',
            field=models.CharField(blank=True, choices=[('Local CA', 'Local CA'), ('Local Cert', 'Local Cert'), ('Remote CA', 'Remote CA'), ('Remote Cert', 'Remote Cert'), ('CRL', 'CRL')], default='', max_length=16),
        ),
    ]
