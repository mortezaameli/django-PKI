from django.contrib import admin
from pki_app import models

admin.site.register(models.PkiObjectModel)
admin.site.register(models.PkiCrlModel)
admin.site.register(models.PkiCaDatabaseModel)
