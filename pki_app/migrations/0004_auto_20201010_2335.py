# Generated by Django 2.2 on 2020-10-10 20:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki_app', '0003_auto_20201010_1518'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='pkiobjectmodel',
            name='is_ca',
        ),
        migrations.RemoveField(
            model_name='pkiobjectmodel',
            name='serial_number',
        ),
        migrations.RemoveField(
            model_name='pkiobjectmodel',
            name='status',
        ),
        migrations.RemoveField(
            model_name='pkiobjectmodel',
            name='subject',
        ),
        migrations.AlterField(
            model_name='pkiobjectmodel',
            name='name',
            field=models.CharField(max_length=128, unique=True),
        ),
    ]
