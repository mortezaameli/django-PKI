from django.shortcuts import render
from django.http import HttpResponse
from django.core.files.base import ContentFile
from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.parsers import FileUploadParser
from rest_framework.parsers import JSONParser
from rest_framework.parsers import FormParser
from rest_framework.parsers import MultiPartParser
from rest_framework.parsers import ParseError
from pki_app import serializers, models
from pki_app.pki_operations import PkiOperations
from pki_app.ssl_utility import SslUtility
import os
import mimetypes
from . import constant, validators

def remove_dir_files(dir_path):
    import glob
    files = glob.glob(os.path.join(dir_path, '*'))
    for f in files:
        os.remove(f)


def remove_file_if_exists(file_path):
    if os.path.isfile(file_path):
        os.remove(file_path)


def get_safe_content_of_file(filename):
    try:
        with open(filename) as fp:
            return fp.read()
    except Exception as e:
        return ''


def safe_write_content_to_file(filename, content):
    try:
        with open(filename, 'w') as fp:
            fp.write(content)
    except Exception as e:
        return ''


def get_ca_db():
    try:
        ca_db = models.PkiCaDatabaseModel.objects.first()
    except models.PkiCaDatabaseModel.DoesNotExist:
        return  None
    return ca_db


def initialize_ca_db():
    ca_db = get_ca_db()
    if ca_db is None:
        ca_db = models.PkiCaDatabaseModel()
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'crlnumber', '01\n')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'crlnumber.old', '')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'index.txt', '')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'index.txt.old', '')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'index.txt.attr', 'unique_subject = no\n')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'index.txt.attr.old', 'unique_subject = no\n')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'serial', '01\n')
    safe_write_content_to_file(constant.PKI_CA_DB_DIR + 'serial.old', '')
    ca_db.save()


def update_ca_db():
    ca_db = get_ca_db()
    if ca_db is None:
        ca_db = models.PkiCaDatabaseModel()
    ca_db.crlnumber = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'crlnumber')
    ca_db.crlnumber_old = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'crlnumber.old')
    ca_db.index_txt = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'index.txt')
    ca_db.index_txt_old = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'index.txt.old')
    ca_db.index_attr = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'index.txt.attr')
    ca_db.index_attr_old = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'index.txt.attr.old')
    ca_db.serial = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'serial')
    ca_db.serial_old = get_safe_content_of_file(constant.PKI_CA_DB_DIR + 'serial.old')
    ca_db.save()
    

def remove_cert_from_ca_db(cert_file):
    """
    remove cert data from openssl ca-db index.txt database
    """
    EXPIRE_DATE_COLUMN = 1
    SERIAL_COLUMN = 3
    cert_expire_date = SslUtility.get_cert_expire_date_asn1_format(cert_file)[2:]
    cert_serial_num = SslUtility.get_cert_serial_number(cert_file)
    try:
        with open(constant.PKI_CA_DB_DIR + 'index.txt') as fp:
            lines = fp.readlines()
    except Exception as e:
        pass
    else:
        with open(constant.PKI_CA_DB_DIR + 'index.txt', 'w') as fp:
            for line in lines:
                line_data = line.split('\t')
                try:
                    if not (
                        line_data[EXPIRE_DATE_COLUMN] == cert_expire_date
                        and int(line_data[SERIAL_COLUMN], 16) == cert_serial_num
                    ):
                        fp.write(line)
                except Exception as e:
                    pass


def get_ca_cert():
    try:
        ca_cert = models.PkiObjectModel.objects.filter(is_ca=True).exclude(key_file='').first()
    except models.PkiObjectModel.DoesNotExist:
        ca_cert = None
    return ca_cert


def get_csr_pair_for_cert(cert_file):
    try:
        csr_without_certs = models.PkiObjectModel.objects.filter(cert_file='').exclude(key_file='')
    except Exception as e:
        return None
    cert_pubkey = SslUtility.get_cert_pubkey(cert_file)
    for csr in csr_without_certs:
        csr_pubkey = SslUtility.get_csr_pubkey(csr.csr_file.name)
        if cert_pubkey == csr_pubkey:
            return csr
    return None


def is_unique_remote_cert(name):
    """
    check remote cert have a unique name
    """
    return not models.PkiObjectModel.objects.filter(
        Q(name=name),
        Q(category=constant.CATEGORY_REMOTE_CERT) | Q(category=constant.CATEGORY_REMOTE_CA),
        ).exists()


def is_unique_local_cert(name):
    """
    check remote cert have a unique name
    """
    return not models.PkiObjectModel.objects.filter(
        Q(name=name),
        Q(category=constant.CATEGORY_LOCAL_CERT) | Q(category=constant.CATEGORY_LOCAL_CA),
        ).exists()


def is_exists_ca_cert():
    return models.PkiObjectModel.objects.filter(is_ca=True).exists()


def get_next_remote_cert_name():
    try:
        remote_certs = models.PkiObjectModel.objects.filter(category=constant.CATEGORY_REMOTE_CERT).order_by('name')
    except models.PkiObjectModel.DoesNotExist:
        return 'REMOTE_Cert_1'
    
    cert_names = []
    for cert in remote_certs:
        cert_names.append(cert.name)
    
    i = 1
    for name in cert_names:
        if name != f'REMOTE_Cert_{i}' and name not in cert_names:
            return f'REMOTE_Cert_{i}'
        i += 1
    return f'REMOTE_Cert_{i}'


def get_next_remote_ca_name():
    try:
        remote_cas = models.PkiObjectModel.objects.filter(category=constant.CATEGORY_REMOTE_CA).order_by('name')
    except models.PkiObjectModel.DoesNotExist:
        return 'CA_Cert_1'
    
    ca_names = []
    for cert in remote_cas:
        ca_names.append(cert.name)
    
    i = 1
    for name in ca_names:
        if name != f'CA_Cert_{i}' and name not in ca_names:
            return f'CA_Cert_{i}'
        i += 1
    return f'CA_Cert_{i}'


def get_next_crl_name():
    try:
        crls = models.PkiCrlModel.objects.all().order_by('name')
    except models.PkiCrlModel.DoesNotExist:
        return 'CRL_1'
    
    crl_names = []
    for crl in crls:
        crl_names.append(crl.name)
    
    i = 1
    for name in crl_names:
        if name != f'CRL_{i}' and name not in crl_names:
            return f'CRL_{i}'
        i += 1
    return f'CRL_{i}'
        
# ------------------------------------------------------------------------------------------

class PkiValidKeyFieldsView(APIView):

    def get(self, request):
        data = {
            'key_types': constant.KEY_TYPES,
            'rsa_key_sizes': constant.RSA_KEY_SIZE,
            'ec_key_sizes': constant.EC_KEY_SIZE
        }
        return Response(data=data, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiValidCertCategoriesView(APIView):

    def get(self, request):
        data = {
            'categories': constant.CERT_CATEGORIES
        }
        return Response(data=data, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiSelfSignView(APIView):

    def post(self, request):
        serializer = serializers.PkiCreateSelfsignSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        new_obj = models.PkiObjectModel()
        new_obj.name = serializer.data.get('name')
        new_obj.category = constant.CATEGORY_LOCAL_CA

        # check cert info is unique
        if not is_unique_local_cert(name=new_obj.name):
            return Response(data={'error': 'Certificate name already in use'}, status=status.HTTP_400_BAD_REQUEST)
        
        # check taht another signer CA isn't exists
        if is_exists_ca_cert():
            return Response(data={'error': 'Connot have two signer CA together'}, status=status.HTTP_400_BAD_REQUEST)

        # TODO: check all field root_ca_info?
        root_ca_info = {
            'name': serializer.data.get('name'),
            'key_type' : serializer.data.get('key_type'),
            'key_size' : serializer.data.get('key_size'),
            'CN' : serializer.data.get('subject_info').get('subject'),
            'O' : serializer.data.get('subject_info').get('organization'),
            'OU' : serializer.data.get('subject_info').get('organization_unit'),
            'L' : serializer.data.get('subject_info').get('locality'),
            'ST' : serializer.data.get('subject_info').get('state'),
            'C' : serializer.data.get('subject_info').get('country'),
            'emailAddress' : serializer.data.get('subject_info').get('email'),
            'validity_days' : serializer.data.get('validity_days'),
            'privkey_pass' : serializer.data.get('privkey_pass', constant.PRIVKEY_DEFAULT_PASS),
        }

        operation_info = PkiOperations.create_selfsign(root_ca_info)
        if operation_info.get('returncode') != 0:
            return Response(data={'err': operation_info.get('stderr')}, status=status.HTTP_400_BAD_REQUEST)
        
        new_obj.cert_file = constant.PKI_CERT_DIR + root_ca_info.get('name') + '.cert'
        try:
            with open(new_obj.cert_file.name) as fp:
                new_obj.cert_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'failed to save cert file in database'}, status=status.HTTP_403_FORBIDDEN)

        new_obj.key_file = constant.PKI_KEY_DIR + root_ca_info.get('name') + '.key'
        try:
            with open(new_obj.key_file.name) as fp:
                new_obj.key_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'Failed to save key file in database'}, status=status.HTTP_403_FORBIDDEN)

        new_obj.save()
        update_ca_db()
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiCsrView(APIView):
    
    def post(self, request):
        serializer = serializers.PkiCreateCsrSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        new_obj = models.PkiObjectModel()
        new_obj.name = serializer.data.get('name')
        new_obj.category = constant.CATEGORY_LOCAL_CERT

        # check new cert info is unique
        if not is_unique_local_cert(name=new_obj.name):
            return Response(data={'error': 'Certificate name already in use'}, status=status.HTTP_400_BAD_REQUEST)
        
        # TODO: check all field csr_info?
        csr_info = {
            'name': serializer.data.get('name'),
            'key_type' : serializer.data.get('key_type'),
            'key_size' : serializer.data.get('key_size'),
            'CN' : serializer.data.get('subject_info').get('subject'),
            'O' : serializer.data.get('subject_info').get('organization'),
            'OU' : serializer.data.get('subject_info').get('organization_unit'),
            'L' : serializer.data.get('subject_info').get('locality'),
            'ST' : serializer.data.get('subject_info').get('state'),
            'C' : serializer.data.get('subject_info').get('country'),
            'emailAddress' : serializer.data.get('subject_info').get('email'),
            'privkey_pass': serializer.data.get('privkey_pass', constant.PRIVKEY_DEFAULT_PASS),
        }

        operation_info = PkiOperations.create_csr(csr_info)
        if operation_info.get('returncode') != 0:
            return Response(data={'err': operation_info.get('stderr')}, status=status.HTTP_400_BAD_REQUEST)

        new_obj.csr_file = constant.PKI_CSR_DIR + new_obj.name + '.csr'
        try:
            with open(new_obj.csr_file.name) as fp:
                new_obj.csr_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'failed to save csr file in database'}, status=status.HTTP_403_FORBIDDEN)

        new_obj.key_file = constant.PKI_KEY_DIR + new_obj.name + '.key'
        try:
            with open(new_obj.key_file.name) as fp:
                new_obj.key_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'failed to save key file in database'}, status=status.HTTP_403_FORBIDDEN)
        
        new_obj.save()
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    # def get(self, request, pk):
    #     try:
    #         select_csr = models.PkiCsrModel.objects.get(pk=pk)
    #     except models.PkiCsrModel.DoesNotExist:
    #         return Response(data={'error': 'csr does not exist'}, status=status.HTTP_404_NOT_FOUND)
    #     csr_info = {
    #         'id': select_csr.id,
    #         'name': select_csr.name,
    #         'subject': select_csr.subject,
    #         'csr_file': select_csr.csr_file.name,
    #         # 'key_file': select_csr.key_file.name,
    #     }
    #     return Response(data=csr_info, status=status.HTTP_200_OK)
    
    # def delete(self, request, pk):
    #     try:
    #         select_csr = models.PkiCsrModel.objects.get(pk=pk)
    #     except models.PkiCsrModel.DoesNotExist:
    #         return Response(data={'error': 'csr does not exist'}, status=status.HTTP_404_NOT_FOUND)
         
    #     select_csr.delete()
    #     return Response(data={'deleted_id': select_csr.id}, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiImportRemoteCsrView(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'csr_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        csr_file = request.data['csr_file']
        
        new_obj = models.PkiObjectModel()
        new_obj.name = get_next_remote_cert_name()
        new_obj.category = constant.CATEGORY_REMOTE_CERT

        # check new cert info is unique
        if not is_unique_remote_cert(name=new_obj.name):
            return Response(data={'error': f"Delete '{new_obj.name}' from remote certificate"}, status=status.HTTP_400_BAD_REQUEST)
        
        new_obj.csr_file.save(constant.PKI_CSR_DIR + new_obj.name + '.csr', csr_file, save=False)

        # check upladed file is a csr file
        if not SslUtility.is_csr_file(new_obj.csr_file.name):
            new_obj.csr_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Incorrect certificate request file format for csr'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with open(new_obj.csr_file.name) as fp:
                new_obj.csr_file_data = fp.read()
        except Exception as err:
            new_obj.csr_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Failed to save csr file in database'}, status=status.HTTP_403_FORBIDDEN)
        
        new_obj.save()
        return Response(status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiImportLocalCertView(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'cert_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        cert_file = request.data['cert_file']

        # create a temp pki model to save straem of cert file to use it
        temp_obj = models.PkiObjectModel()
        temp_obj.cert_file.save(constant.PKI_CERT_DIR + cert_file.name, cert_file, save=False)
        
        # check upladed file is a cert file
        if not SslUtility.is_cert_file(temp_obj.cert_file.name):
            temp_obj.cert_file.delete(save=False)
            return Response(data={'err': 'Incorrect certificate file format for cert'}, status=status.HTTP_400_BAD_REQUEST)
        
        # find csr pair(pki_object) for uploaded cert
        pki_obj = get_csr_pair_for_cert(temp_obj.cert_file.name)
        if pki_obj is None:
            temp_obj.cert_file.delete(save=False)
            return Response(data={'err': 'Key pair mismatch for local cert'}, status=status.HTTP_400_BAD_REQUEST)
        
        pki_obj.cert_file.save(constant.PKI_CERT_DIR + pki_obj.name + '.cert', ContentFile(temp_obj.cert_file.read()), save=False)
        pki_obj.cert_file_data = pki_obj.cert_file.read().decode('utf-8')
        pki_obj.save()
        temp_obj.cert_file.delete(save=False)
        
        return Response(status=status.HTTP_201_CREATED)
        
# ------------------------------------------------------------------------------------------

class PkiImportRemoteCaView(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'ca_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        ca_file = request.data['ca_file']

        new_obj = models.PkiObjectModel()
        new_obj.name = get_next_remote_ca_name()
        new_obj.category = constant.CATEGORY_REMOTE_CA

        # check new cert info is unique
        if not is_unique_remote_cert(name=new_obj.name):
            return Response(data={'error': f"Delete '{new_obj.name}' from remote CA certificate"}, status=status.HTTP_400_BAD_REQUEST)
        
        new_obj.cert_file.save(constant.PKI_TRUSTED_DIR + new_obj.name + '.cert', ca_file, save=False)
        
        # check uploaded file is a cert file
        if not SslUtility.is_cert_file(new_obj.cert_file.name):
            new_obj.cert_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Incorrect certificate file format for CA'}, status=status.HTTP_400_BAD_REQUEST)
        
        # check uploaded file have a subject_hash and change filename
        # Trusted ca must be save in CERTNAME.0 format base on openssl documents
        remote_ca_filename = SslUtility.get_subject_hash_cert(new_obj.cert_file.name)
        if remote_ca_filename is None:
            new_obj.cert_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Incorrect certificate file format for CA'}, status=status.HTTP_400_BAD_REQUEST)
        os.rename(new_obj.cert_file.name, constant.PKI_TRUSTED_DIR + remote_ca_filename + '.0')
        new_obj.cert_file = constant.PKI_TRUSTED_DIR + remote_ca_filename + '.0'
        
        try:
            with open(new_obj.cert_file.name) as fp:
                new_obj.cert_file_data = fp.read()
        except Exception as err:
            new_obj.cert_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Failed to save ca cert file in database'}, status=status.HTTP_403_FORBIDDEN)
        
        new_obj.save()
        return Response(status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiImportCrlView(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'crl_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        crl_file = request.data['crl_file']

        temp_crl = models.PkiCrlModel()
        temp_crl.name = get_next_crl_name()
        temp_crl.crl_file.save(constant.PKI_TRUSTED_DIR + temp_crl.name + '.crl', crl_file, save=False)
        
        # check uploaded file is a crl file
        if not SslUtility.is_crl_file(temp_crl.crl_file.name):
            temp_crl.crl_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Incorrect CRL file format'}, status=status.HTTP_400_BAD_REQUEST)
        
        # if crl can be verified it can be add to trusted
        if not SslUtility.crl_verify(temp_crl.crl_file.name):
            return Response(data={'error': "CRL file doesn't have matched CA imported"}, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_crl_hash = SslUtility.get_issuer_hash_crl(temp_crl.crl_file.name)
        if uploaded_crl_hash is None:
            return Response(data={'error': 'Incorrect CRL file format'}, status=status.HTTP_400_BAD_REQUEST)
        
        new_crl = None
        crls = models.PkiCrlModel.objects.all()
        for crl in crls:
            if uploaded_crl_hash == SslUtility.get_issuer_hash_crl(crl.crl_file.name):
                new_crl = crl
                break

        # if crl already not exists
        if new_crl is None:
            new_crl = temp_crl
        else:
            new_crl.crl_file = temp_crl.crl_file

        os.rename(new_crl.crl_file.name, constant.PKI_TRUSTED_DIR + uploaded_crl_hash + '.r0')
        new_crl.crl_file = constant.PKI_TRUSTED_DIR + uploaded_crl_hash + '.r0'

        try:
            with open(new_crl.crl_file.name) as fp:
                new_crl.crl_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'Failed to save crl file in database'}, status=status.HTTP_403_FORBIDDEN)
        
        new_crl.save()
        return Response(status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiImportP12View(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'p12_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        p12_file = request.data['p12_file']

        if 'p12_pass' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        p12_pass = request.data['p12_pass']

        if 'cert_name' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        cert_name = request.data['cert_name']

        new_obj = models.PkiObjectModel()
        
        # TODO: check cert_name with name field validator before using it
        new_obj.name = cert_name

        # check new cert info is unique in local certs
        if not is_unique_local_cert(name=new_obj.name):
            return Response(data={'error': 'Certificate name already in use'}, status=status.HTTP_400_BAD_REQUEST)

        temp_p12_file = constant.PKI_TMP_DIR + 'TEMP.p12'

        # save upladed p2 file in a temporary path to procceess it
        try:
            with open(temp_p12_file, 'wb') as fp:
                fp.write(p12_file.read())
        except Exception as e:
            return Response(data={'error': 'Failed to get uploaded file'}, status=status.HTTP_400_BAD_REQUEST)

        export_key_path = constant.PKI_TMP_DIR + 'TEMP.key'
        export_cert_path = constant.PKI_TMP_DIR + 'TEMP.cert'

        if not SslUtility.is_p12_file(temp_p12_file):
            return Response(data={'error': 'Incorrect p12 file format'}, status=status.HTTP_400_BAD_REQUEST)

        if not SslUtility.parse_p12file(temp_p12_file, p12_pass, export_cert_path, export_key_path):
            return Response(data={'error': 'Parse PKCS12 certificate file error'}, status=status.HTTP_400_BAD_REQUEST)

        if SslUtility.is_CA_cert(export_cert_path):
            new_obj.category = constant.CATEGORY_LOCAL_CA
        else:
            new_obj.category = constant.CATEGORY_LOCAL_CERT

        # save key_file and key_file_data in model
        try:
            with open(export_key_path, 'rb') as fp:
                new_obj.key_file.save(constant.PKI_KEY_DIR + new_obj.name + '.key', fp, save=False)
        except Exception as e:
            new_obj.key_file.delete(save=False)
            return Response(data={'error': 'Failed to save key file in database'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with open(new_obj.key_file.name) as fp:
                new_obj.key_file_data = fp.read()
        except Exception as e:
            new_obj.key_file.delete(save=False)
            return Response(data={'error': 'Failed to save key file in database'}, status=status.HTTP_400_BAD_REQUEST)
        
        # save cert_file and cert_file_data in model
        try:
            with open(export_cert_path, 'rb') as fp:
                new_obj.cert_file.save(constant.PKI_CERT_DIR + new_obj.name + '.cert', fp, save=False)
        except Exception as e:
            new_obj.cert_file.delete(save=False)
            return Response(data={'error': 'Failed to save certificate file in database'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with open(new_obj.cert_file.name) as fp:
                new_obj.cert_file_data = fp.read()
        except Exception as e:
            new_obj.key_file.delete(save=False)
            new_obj.cert_file.delete(save=False)
            return Response(data={'error': 'Failed to save certificate file in database'}, status=status.HTTP_400_BAD_REQUEST)
        
        remove_dir_files(constant.PKI_TMP_DIR)

        new_obj.save()
        return Response(status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiImportLocalCertWithKeyView(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'cert_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        cert_file = request.data['cert_file']

        if 'key_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        key_file = request.data['key_file']

        key_pass = ''
        if 'key_pass' in request.data:
            key_pass = request.data['key_pass']

        if 'cert_name' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        cert_name = request.data['cert_name']

        new_obj = models.PkiObjectModel()
        new_obj.name = cert_name

        ok, err = validators.PkiValidators.check_cert_name(new_obj.name)
        if not ok:
            return Response(data={'error': err}, status=status.HTTP_404_NOT_FOUND)

        # check new cert info is unique in local certs
        if not is_unique_local_cert(name=new_obj.name):
            return Response(data={'error': 'Certificate name already in use'}, status=status.HTTP_400_BAD_REQUEST)

        # save cert_file in model
        remove_file_if_exists(constant.PKI_CERT_DIR + new_obj.name + '.cert')
        new_obj.cert_file.save(constant.PKI_CERT_DIR + new_obj.name + '.cert', cert_file, save=False)
        try:
            with open(new_obj.cert_file.name) as fp:
                new_obj.cert_file_data = fp.read()
        except Exception as e:
            return Response(data={'error': 'Failed to save certificate file in database'}, status=status.HTTP_400_BAD_REQUEST)

        # save key file in a temporary path to encrypt it if not encrypt
        temp_key_file = constant.PKI_TMP_DIR + 'TEMP.key'
        try:
            with open(temp_key_file, 'wb') as fp:
                fp.write(key_file.read())
        except Exception as e:
            return Response(data={'error': 'Failed to get uploaded privkey file'}, status=status.HTTP_400_BAD_REQUEST)

        key_is_encrypted = True
        key_new_pass = ''

        if not SslUtility.is_encrypted_key(temp_key_file):
            key_is_encrypted = False
            if key_pass != '':
                key_new_pass = key_pass
            else:
                key_new_pass = constant.PRIVKEY_DEFAULT_PASS

        if key_is_encrypted:
            if not SslUtility.is_pkey_pass_correct(temp_key_file, key_pass):
                return Response(data={'error': 'Failed to open privkey file'}, status=status.HTTP_400_BAD_REQUEST)

        if key_new_pass == '':
            new_encripted_key = temp_key_file
        else:
            new_encripted_key = SslUtility.create_encrypted_key(
                key_file=temp_key_file,
                encrypted_key=constant.PKI_TMP_DIR + 'NEW_TEMP.key',
                key_pass=key_new_pass
            )
            if new_encripted_key is None:
                return Response(data={'error': 'Failed to encrypt privkey with this password'}, status=status.HTTP_400_BAD_REQUEST)

        # save new_encripted_key in model
        remove_file_if_exists(constant.PKI_KEY_DIR + new_obj.name + '.key')
        try:
            with open(new_encripted_key, 'rb') as fp:
                new_obj.key_file.save(constant.PKI_KEY_DIR + new_obj.name + '.key', fp, save=False)
        except Exception as e:
            return Response(data={'error': 'Failed to save privkey file in database'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            with open(new_obj.key_file.name) as fp:
                new_obj.key_file_data = fp.read()
        except Exception as e:
            return Response(data={'error': 'Failed to save privkey file in database'}, status=status.HTTP_400_BAD_REQUEST)

        if not SslUtility.is_cert_file(new_obj.cert_file.name):
            return Response(data={'error': 'Incorrect certificate file format'}, status=status.HTTP_400_BAD_REQUEST)

        # check pubkey of key and cert is equal
        cert_pubkey = SslUtility.get_cert_pubkey(new_obj.cert_file.name)
        privkey_pubkey = SslUtility.get_privkey_pubkey(new_obj.key_file.name, key_new_pass)
        if cert_pubkey != privkey_pubkey:
            return Response(data={'error': 'Key pair mismatch for local cert'}, status=status.HTTP_400_BAD_REQUEST)

        if SslUtility.is_CA_cert(new_obj.cert_file.name):
            new_obj.category = constant.CATEGORY_LOCAL_CA
        else:
            new_obj.category = constant.CATEGORY_LOCAL_CERT

        remove_dir_files(constant.PKI_TMP_DIR)
        new_obj.save()
        return Response(status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiImportRemoteCertView(APIView):

    parser_classes = (MultiPartParser,)

    def put(self, request, format=None):
        if 'cert_file' not in request.data:
            return Response(data=request.data, status=status.HTTP_400_BAD_REQUEST)
        cert_file = request.data['cert_file']

        new_obj = models.PkiObjectModel()
        new_obj.name = get_next_remote_cert_name()
        new_obj.category = constant.CATEGORY_REMOTE_CERT

        # check new cert info is unique
        if not is_unique_remote_cert(name=new_obj.name):
            return Response(data={'error': f"Delete '{new_obj.name}' from remote certificate"}, status=status.HTTP_400_BAD_REQUEST)

        remove_file_if_exists(constant.PKI_CERT_DIR + new_obj.name + '.cert')
        new_obj.cert_file.save(constant.PKI_CERT_DIR + new_obj.name + '.cert', cert_file, save=False)

        # check upladed file is a cert file
        if not SslUtility.is_cert_file(new_obj.cert_file.name):
            new_obj.cert_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Incorrect certificate file format'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with open(new_obj.cert_file.name) as fp:
                new_obj.cert_file_data = fp.read()
        except Exception as err:
            new_obj.cert_file.delete(save=False)   # delete incorrect file
            return Response(data={'error': 'Failed to save certificate file in database'}, status=status.HTTP_403_FORBIDDEN)

        new_obj.save()
        return Response(status=status.HTTP_201_CREATED)

# ------------------------------------------------------------------------------------------

class PkiSignCsrView(APIView):

    def post(self, request):
        serializer = serializers.PkiSignCsrSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # check have a object with this cert name
        try:
            select_obj = models.PkiObjectModel.objects.get(
                category=serializer.data.get('category'),
                name=serializer.data.get('name')
            )
        except models.PkiObjectModel.DoesNotExist:
            return Response(data={'error': 'CSR does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        # local intermediate CA must be located in local CA category
        if serializer.data.get('can_sign') == True:
            if select_obj.category == constant.CATEGORY_LOCAL_CERT:
                select_obj.category = constant.CATEGORY_LOCAL_CA

        # check requested cert is exist already
        if select_obj.cert_file != '':
            return Response(data={'error': 'Certificate already exists'}, status=status.HTTP_403_FORBIDDEN)
        
        select_obj.cert_file = constant.PKI_CERT_DIR + select_obj.name + '.cert'
        
        ca_cert = get_ca_cert()
        if ca_cert is None:
            return Response(data={'error': 'CA certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)
        ca_info = {
            'cert_file': ca_cert.cert_file.name,
            'key_file': ca_cert.key_file.name,
            'ca_privkey_pass': serializer.data.get('ca_privkey_pass', constant.PRIVKEY_DEFAULT_PASS),
        }

        if not SslUtility.is_pkey_pass_correct(ca_info['key_file'], ca_info['ca_privkey_pass']):
            return Response(data={'error': 'CA privkey password not correct'}, status=status.HTTP_403_FORBIDDEN)
        
        new_cert_info = {
            'name': select_obj.name,
            'csr_file': select_obj.csr_file.name,
            'can_sign': serializer.data.get('can_sign'),
            'validity_days' : serializer.data.get('validity_days'),
            'new_cert_file': select_obj.cert_file.name,
        }

        operation_info = PkiOperations.sign_csr(ca_info, new_cert_info)
        if operation_info.get('returncode') != 0:
            return Response(data={'error': operation_info.get('stderr')}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with open(select_obj.cert_file.name) as fp:
                select_obj.cert_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'failed to save cert file in database'}, status=status.HTTP_403_FORBIDDEN)
        
        select_obj.save()
        update_ca_db()
        remove_dir_files(constant.PKI_TMP_DIR)
        return Response(data={'info': 'ok'}, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiRevokeLocalCertView(APIView):

    def post(self, request):
        serializer = serializers.PkiRevokeCertSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # check have a object with this cert name
        try:
            select_obj = models.PkiObjectModel.objects.get(
                category=serializer.data.get('category'),
                name=serializer.data.get('name')
            )
        except models.PkiObjectModel.DoesNotExist:
            return Response(data={'error': 'Certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)

        # check cert is exist in pki object
        if select_obj.cert_file == '':
            return Response(data={'error': 'Certificate file does not exist'}, status=status.HTTP_403_FORBIDDEN)

        ca_cert = get_ca_cert()
        if ca_cert is None:
            return Response(data={'error': 'CA cert does not exist'}, status=status.HTTP_404_NOT_FOUND)
        ca_info = {
            'cert_file': ca_cert.cert_file.name,
            'key_file': ca_cert.key_file.name,
            'ca_privkey_pass': serializer.data.get('ca_privkey_pass', constant.PRIVKEY_DEFAULT_PASS),
        }

        if not SslUtility.is_pkey_pass_correct(ca_info['key_file'], ca_info['ca_privkey_pass']):
            return Response(data={'error': 'CA privkey password not correct'}, status=status.HTTP_403_FORBIDDEN)

        cert_info = {
            'name': select_obj.name,
            'cert_file': select_obj.cert_file.name,
        }

        if not SslUtility.check_cert_signed_by_ca(cert_info['cert_file'], ca_info['cert_file']):
            return Response(data={'error': "This certificate has been signed by another CA"}, status=status.HTTP_403_FORBIDDEN)

        # TODO: check serial number exist in ca-db/index.txt

        operation_info = PkiOperations.revoke_cert(ca_info, cert_info)
        if operation_info.get('returncode') != 0:
            return Response(data={'error': operation_info.get('stderr')}, status=status.HTTP_400_BAD_REQUEST)

        # TODO: search for `openssl ca updatedb` (Add if needed)

        update_ca_db()
        return Response(data={'info': 'ok'}, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiCreateCrlView(APIView):

    def post(self, request):

        serializer = serializers.PkiCreateCrlSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        ca_cert = get_ca_cert()
        if ca_cert is None:
            return Response(data={'error': 'CA cert does not exist'}, status=status.HTTP_404_NOT_FOUND)
        ca_info = {
            'name': ca_cert.name,
            'cert_file': ca_cert.cert_file.name,
            'key_file': ca_cert.key_file.name,
            'ca_privkey_pass': serializer.data.get('ca_privkey_pass', constant.PRIVKEY_DEFAULT_PASS),
            'validity_days': SslUtility.get_validaty_days(ca_cert.cert_file.name),
        }

        if not SslUtility.is_pkey_pass_correct(ca_info['key_file'], ca_info['ca_privkey_pass']):
            return Response(data={'error': 'CA privkey password not correct'}, status=status.HTTP_403_FORBIDDEN)
        
        operation_info = PkiOperations.create_crl(ca_info)
        if operation_info.get('returncode') != 0:
            return Response(data={'error': operation_info.get('stderr')}, status=status.HTTP_400_BAD_REQUEST)
        
        crl_file = constant.PKI_TRUSTED_DIR + ca_info.get('name') + '.crl'

        if not os.path.isfile(crl_file):
            return Response(data={'error': 'Failed to generate CRL'}, status=status.HTTP_400_BAD_REQUEST)
        
        # check generated file is a crl file
        if not SslUtility.is_crl_file(crl_file):
            return Response(data={'error': 'Failed to generate CRL file'}, status=status.HTTP_400_BAD_REQUEST)
        
        # if crl can be verified it can be add to trusted
        if not SslUtility.crl_verify(crl_file):
            return Response(data={'error': "CRL file doesn't have matched CA imported"}, status=status.HTTP_400_BAD_REQUEST)
        
        generated_crl_hash = SslUtility.get_issuer_hash_crl(crl_file)
        if generated_crl_hash is None:
            return Response(data={'error': 'Failed to generated CRL'}, status=status.HTTP_400_BAD_REQUEST)
        
        new_crl = None
        crls = models.PkiCrlModel.objects.all()
        for crl in crls:
            if generated_crl_hash == SslUtility.get_issuer_hash_crl(crl.crl_file.name):
                new_crl = crl
                break
        
        if new_crl is None:
            new_crl = models.PkiCrlModel()
            new_crl.name = get_next_crl_name()

        os.rename(crl_file, constant.PKI_TRUSTED_DIR + generated_crl_hash + '.r0')
        new_crl.crl_file = constant.PKI_TRUSTED_DIR + generated_crl_hash + '.r0'
       
        # TODO: think about when exists crl with same issuer hash!

        try:
            with open(new_crl.crl_file.name) as fp:
                new_crl.crl_file_data = fp.read()
        except Exception as err:
            return Response(data={'err': 'failed to save crl file in database'}, status=status.HTTP_403_FORBIDDEN)
        
        new_crl.save()
        return Response(status=status.HTTP_201_CREATED)

# ----------------------------------------------------------------

class PkiIssuerCaView(APIView):

    def get(self, request):
        ca_cert = get_ca_cert()
        if ca_cert is None:
            return Response(data={'error': 'Issuer CA certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)
        if ca_cert.cert_file == '':
            return Response(data={'error': 'Issuer CA certificate file does not exist'}, status=status.HTTP_404_NOT_FOUND)
        subject = SslUtility.get_cert_subject(ca_cert.cert_file.name)
        issuer = SslUtility.get_cert_issuer(ca_cert.cert_file.name)
        ca_info = {
            'id': ca_cert.id,
            'name': ca_cert.name,
            'comment': ca_cert.comment,
            'subject': subject,
            'issuer': issuer,
        }
        return Response(data=ca_info, status=status.HTTP_200_OK)

    def put(self, request, name):
        try:
            select_cert = models.PkiObjectModel.objects.get(category=constant.CATEGORY_LOCAL_CA, name=name)
        except models.PkiObjectModel.DoesNotExist:
            return Response(data={'error': 'CA Certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        ca_cert = get_ca_cert()
        if ca_cert is not None:
            return Response(data={'error': 'Issuer CA certificate has been specified already'}, status=status.HTTP_403_FORBIDDEN)
        
        select_cert.is_ca = True
        select_cert.save()
        return Response(status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiCertsListView(APIView):

    def get(self, request):
        certs = models.PkiObjectModel.objects.all()
        data = []
        for cert in certs:
            have_cert = True
            subject = ''
            issuer = ''
            expire_date = ''
            if cert.cert_file == '':
                have_cert = False
            if have_cert:
                subject = SslUtility.get_cert_subject(cert.cert_file.name)
                issuer = SslUtility.get_cert_issuer(cert.cert_file.name)
                expire_date = SslUtility.get_cert_expire_date(cert.cert_file.name)
            data.append(
                {
                    'id': cert.id,
                    'category': cert.category,
                    'name': cert.name,
                    'comment': cert.comment,
                    'subject': subject,
                    'issuer': issuer,
                    'expires': expire_date,
                }
            )
        return Response(data=data, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiCertView(APIView):

    def get(self, request, category, name):
        ok, err = validators.PkiValidators.check_cert_category(category)
        if not ok:
            return Response(data={'error': err}, status=status.HTTP_404_NOT_FOUND)
        try:
            select_cert = models.PkiObjectModel.objects.get(category=category, name=name)
        except models.PkiObjectModel.DoesNotExist:
            return Response(data={'error': 'Certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)

        cert_utils = SslUtility.CertUtils(select_cert.cert_file.name)
        cert_info = {
            'id': select_cert.id,
            'name': select_cert.name,
            'version': cert_utils.get_version(),
            'serial': hex(cert_utils.get_serial_number()).lstrip('0x').upper(),
            'subject': cert_utils.get_subject(),
            'issuer': cert_utils.get_issuer(),
            'valid_from': cert_utils.get_not_before_date(),
            'valid_to': cert_utils.get_not_after_date(),
            'md5_fingerprint': cert_utils.get_md5_fingerprint(),
            'extensions': cert_utils.get_extensions(),
        }
        return Response(data=cert_info, status=status.HTTP_200_OK)
    
    def delete(self, request, category, name):
        ok, err = validators.PkiValidators.check_cert_category(category)
        if not ok:
            return Response(data={'error': err}, status=status.HTTP_404_NOT_FOUND)
        try:
            select_cert = models.PkiObjectModel.objects.get(category=category, name=name)
        except models.PkiObjectModel.DoesNotExist:
            return Response(data={'error': 'Certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)

        if select_cert.category != constant.CATEGORY_REMOTE_CA:
            remove_cert_from_ca_db(select_cert.cert_file.name)
        
        if select_cert.is_ca:
            initialize_ca_db()

        select_cert.delete()
        update_ca_db()

        return Response(data={'deleted_id': select_cert.id}, status=status.HTTP_200_OK)

# ------------------------------------------------------------------------------------------

class PkiCrlsListView(APIView):

    def get(self, request):
        crls = models.PkiCrlModel.objects.all()
        data = []
        for crl in crls:
            crl_utils = SslUtility.CrlUtils(crl.crl_file.name)
            data.append(
                {
                    'id': crl.id,
                    'name': crl.name,
                    'comment': crl.comment,
                    'issuer': crl_utils.get_issuer_short_format(),
                }
            )
        return Response(data=data, status=status.HTTP_200_OK)

#------------------------------------------------------------------------------------------

class PkiCrlView(APIView):

    def get(self, request, name):
        try:
            select_crl = models.PkiCrlModel.objects.get(name=name)
        except models.PkiCrlModel.DoesNotExist:
            return Response(data={'error': 'CRL does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        data = []
        crl_utils = SslUtility.CrlUtils(select_crl.crl_file.name)
        data.append(
            {
                'id': select_crl.id,
                'name': select_crl.name,
                'comment': select_crl.comment,
                'issuer_dn': crl_utils.get_issuer_dn(),
                'revoked_serials': crl_utils.get_revoked_certs_serial(),
                'crl_number': crl_utils.get_crl_number(),
                'last_update': crl_utils.get_last_update(),
                'next_update': crl_utils.get_next_update(),
            }
        )
        return Response(data=data, status=status.HTTP_200_OK)
    
    def delete(self, request, name):
        try:
            select_crl = models.PkiCrlModel.objects.get(name=name)
        except models.PkiCrlModel.DoesNotExist:
            return Response(data={'error': 'CRL does not exist'}, status=status.HTTP_404_NOT_FOUND)
        select_crl.delete()
        return Response(data={'deleted_id': select_crl.id}, status=status.HTTP_200_OK)

#------------------------------------------------------------------------------------------

class PkiIssuerCaFileDownloadView(APIView):
    
    def get(self, request):
        ca_cert = get_ca_cert()
        if ca_cert is None:
            return Response(data={'error': 'Issuer CA certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)
        if ca_cert.cert_file == '':
            return Response(data={'error': 'Issuer CA certificate file does not exist'}, status=status.HTTP_404_NOT_FOUND)
        mime_type = 'application/x-x509-ca-cert'
        with open(ca_cert.cert_file.name) as fp:
            response = HttpResponse(fp, content_type=mime_type)
            response['Content-Disposition'] = f"attachment; filename={ca_cert.name}.cer"
        return response

# ------------------------------------------------------------------------------------------

class PkiP12FileDownloaView(APIView):
    
    def get(self, request):
        serializer = serializers.PkiDownloadP12Serializer(data=request.data)
        if not serializer.is_valid():
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            select_obj = models.PkiObjectModel.objects.get(
                Q(name=serializer.data.get('name')),
                Q(category=constant.CATEGORY_LOCAL_CERT) | Q(category=constant.CATEGORY_LOCAL_CA),
            )
        except models.PkiObjectModel.DoesNotExist as e:
            return Response(data={'error': 'Certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)

        p12_info = {
            'p12_file': constant.PKI_TMP_DIR + select_obj.name + '.p12',
            'p12pass': serializer.data.get('p12pass'),
            'cert_file': select_obj.cert_file.name,
            'key_file': select_obj.key_file.name,
            'privkey_pass' : serializer.data.get('privkey_pass', constant.PRIVKEY_DEFAULT_PASS),
        }

        if not SslUtility.is_pkey_pass_correct(p12_info['key_file'], p12_info['privkey_pass']):
            return Response(data={'error': 'Certificate privkey password not correct'}, status=status.HTTP_403_FORBIDDEN)
        
        if not SslUtility.is_cert_file(p12_info['cert_file']):
            return Response(data={'error': 'Certificate file does not exist'}, status=status.HTTP_404_NOT_FOUND)

        operation_info = PkiOperations.create_p12(p12_info)
        if operation_info.get('returncode') != 0:
            return Response(data={'err': operation_info.get('stderr')}, status=status.HTTP_400_BAD_REQUEST)

        try:
            mime_type = 'application/x-pkcs12'
            with open(p12_info['p12_file'], 'rb') as fp:
                response = HttpResponse(fp, content_type=mime_type)
                response['Content-Disposition'] = f"attachment; filename={select_obj.name}.p12"
        except Exception as e:
            return Response(data={'error': 'Failed to download p12 file'}, status=status.HTTP_404_NOT_FOUND)

        if os.path.isfile(p12_info['p12_file']):
            os.remove(p12_info['p12_file'])

        return response

# ------------------------------------------------------------------------------------------

class PkiCrlFileDownloaView(APIView):
    
    def get(self, request, name):
        try:
            select_crl = models.PkiCrlModel.objects.get(name=name)
        except models.PkiCrlModel.DoesNotExist:
            return Response(data={'error': 'CRL does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        if select_crl.crl_file == '':
            return Response(data={'error': 'CRL file does not exist'}, status=status.HTTP_404_NOT_FOUND)
        try:
            mime_type = 'application/pkix-crl'
            with open(select_crl.crl_file.name) as fp:
                response = HttpResponse(fp, content_type=mime_type)
                response['Content-Disposition'] = f"attachment; filename={select_crl.name}.crl"
        except Exception as e:
            return Response(data={'error': 'Failed to download CRL file'}, status=status.HTTP_404_NOT_FOUND)
        return response

# ------------------------------------------------------------------------------------------

class PkiCertAndCsrFileDownloadView(APIView):
    
    def get(self, request, category, name):
        ok, err = validators.PkiValidators.check_cert_category(category)
        if not ok:
            return Response(data={'error': err}, status=status.HTTP_404_NOT_FOUND)
        try:
            select_obj = models.PkiObjectModel.objects.get(category=category, name=name)
        except models.PkiObjectModel.DoesNotExist:
            return Response(data={'error': 'Certificate does not exist'}, status=status.HTTP_404_NOT_FOUND)
        file_for_download = ''
        file_extension = ''
        if select_obj.cert_file != '':
            file_for_download = select_obj.cert_file.name
            file_extension = 'cer'
            mime_type = 'application/x-x509-ca-cert'
        elif select_obj.csr_file != '':
            file_for_download = select_obj.csr_file.name
            file_extension = 'csr'
            mime_type = 'application/pkcs10'
        else:
            return Response(data={'error': 'cert or csr file does not exist'}, status=status.HTTP_404_NOT_FOUND)

        with open(file_for_download) as fp:
            response = HttpResponse(fp, content_type=mime_type)
            response['Content-Disposition'] = f"attachment; filename={select_obj.name}.{file_extension}"
        return response

# ------------------------------------------------------------------------------------------
