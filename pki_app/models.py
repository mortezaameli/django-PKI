from django.db import models
from . import constant
import os


class PkiObjectModel(models.Model):

    CERT_CATEGORY = [
        (constant.CATEGORY_LOCAL_CA, constant.CATEGORY_LOCAL_CA),
        (constant.CATEGORY_LOCAL_CERT, constant.CATEGORY_LOCAL_CERT),
        (constant.CATEGORY_REMOTE_CA, constant.CATEGORY_REMOTE_CA),
        (constant.CATEGORY_REMOTE_CERT, constant.CATEGORY_REMOTE_CERT),
    ]

    category = models.CharField(max_length=16, choices=CERT_CATEGORY, blank=False)
    name = models.CharField(max_length=64, blank=False)
    key_file = models.FileField(max_length=128, default='', blank=True)
    key_file_data = models.TextField(default='', blank=True)
    cert_file = models.FileField(max_length=128, default='', blank=True)
    cert_file_data = models.TextField(default='', blank=True)
    csr_file = models.FileField(max_length=128, default='', blank=True)
    csr_file_data = models.TextField(default='', blank=True)
    comment = models.TextField(default='', blank=True)
    is_ca = models.BooleanField(default=False)

    def delete(self, using=None, keep_parents=False):
        if os.path.isfile(self.key_file.name):
            self.key_file.storage.delete(self.key_file.name)
        if os.path.isfile(self.cert_file.name):
            self.cert_file.storage.delete(self.cert_file.name)
        if os.path.isfile(self.csr_file.name):
            self.csr_file.storage.delete(self.csr_file.name)
        super().delete()


class PkiCrlModel(models.Model):
    name = models.CharField(max_length=32, blank=False)
    crl_file = models.FileField(max_length=128, default='', blank=True)
    crl_file_data = models.TextField(default='', blank=True)
    comment = models.TextField(default='', blank=True)

    def delete(self, using=None, keep_parents=False):
        if os.path.isfile(self.crl_file.name):
            self.crl_file.storage.delete(self.crl_file.name)
        super().delete()


class PkiCaDatabaseModel(models.Model):
    crlnumber = models.TextField(default='')
    crlnumber_old = models.TextField(default='')
    index_txt = models.TextField(default='')
    index_txt_old = models.TextField(default='')
    index_attr = models.TextField(default='')
    index_attr_old = models.TextField(default='')
    serial = models.TextField(default='')
    serial_old = models.TextField(default='')
