# Generated by Django 2.2 on 2020-11-15 15:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki_app', '0013_auto_20201110_1543'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pkiobjectmodel',
            name='cert_file',
            field=models.FileField(blank=True, default='', max_length=256, upload_to=''),
        ),
        migrations.AlterField(
            model_name='pkiobjectmodel',
            name='csr_file',
            field=models.FileField(blank=True, default='', max_length=256, upload_to=''),
        ),
        migrations.AlterField(
            model_name='pkiobjectmodel',
            name='key_file',
            field=models.FileField(blank=True, default='', max_length=256, upload_to=''),
        ),
    ]