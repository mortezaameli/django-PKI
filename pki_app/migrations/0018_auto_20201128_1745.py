# Generated by Django 2.2 on 2020-11-28 14:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki_app', '0017_auto_20201127_2252'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pkiobjectmodel',
            name='category',
            field=models.CharField(choices=[('Local-CA', 'Local-CA'), ('Local-Cert', 'Local-Cert'), ('Remote-CA', 'Remote-CA'), ('Remote-Cert', 'Remote-Cert')], max_length=16),
        ),
    ]
