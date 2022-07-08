from django.core.management.base import BaseCommand, CommandError
from pki_app import models
from pki_app import constant

class Command(BaseCommand):
    help = 'Load databse files'

    def load_file(self, filename, file_data):
        try:
            with open(filename, 'w') as fp:
                fp.write(file_data)
        except Exception as e:
            pass

    def handle(self, *args, **options):
        
        # load PkiObjectModel files
        objects = models.PkiObjectModel.objects.all()
        for obj in objects:
            self.load_file(obj.key_file.name, obj.key_file_data)
            self.load_file(obj.cert_file.name, obj.cert_file_data)
            self.load_file(obj.csr_file.name, obj.csr_file_data)
        
        # load PkiCrlModel files
        crls = models.PkiCrlModel.objects.all()
        for crl in crls:
            self.load_file(crl.crl_file.name, crl.crl_file_data)
        
        # load PkiCrlModel files
        try:
            ca_db = models.PkiCaDatabaseModel.objects.first()
        except models.PkiCaDatabaseModel.DoesNotExist:
            pass
        else:
            self.load_file(constant.PKI_CA_DB_DIR + 'crlnumber', ca_db.crlnumber)
            self.load_file(constant.PKI_CA_DB_DIR + 'crlnumber.old', ca_db.crlnumber_old)
            self.load_file(constant.PKI_CA_DB_DIR + 'index.txt', ca_db.index_txt)
            self.load_file(constant.PKI_CA_DB_DIR + 'index.txt.old', ca_db.index_txt_old)
            self.load_file(constant.PKI_CA_DB_DIR + 'index.txt.attr', ca_db.index_attr)
            self.load_file(constant.PKI_CA_DB_DIR + 'index.txt.attr.old', ca_db.index_attr_old)
            self.load_file(constant.PKI_CA_DB_DIR + 'serial', ca_db.serial)
            self.load_file(constant.PKI_CA_DB_DIR + 'serial.old', ca_db.serial_old)

        self.stdout.write(self.style.SUCCESS('Successfully load database files'))
        return