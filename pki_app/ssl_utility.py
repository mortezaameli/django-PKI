import subprocess
import os
from dateutil import tz
from datetime import datetime
from . import constant
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (
        load_certificate, load_privatekey, load_certificate_request,
        load_crl, load_pkcs12,
    )

class SslUtility:
    """
    A Class that provide sll utility with openssl and pyOpenssl
    """

    @staticmethod
    def get_csr_pubkey(csr_file):
        """
        Get public key from a csr
        """
        if not os.path.isfile(csr_file):
            return None
        command_params = [
            'openssl', 'req', '-pubkey', '-noout',
            '-outform', 'pem'
            '-in', csr_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if  process.returncode == 0 :
            return stdout.decode('utf-8').rstrip('\n')
        else:
            return None
    
    @staticmethod
    def get_cert_pubkey(cert_file):
        """
        Get public key from a cert
        """
        if not os.path.isfile(cert_file):
            return None
        command_params = [
            'openssl', 'x509',
            '-pubkey', '-noout',
            '-outform', 'pem'
            '-in', cert_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if  process.returncode == 0 :
            return stdout.decode('utf-8').rstrip('\n')
        else:
            return None
    
    @staticmethod
    def get_privkey_pubkey(key_file, key_pass):
        """
        Get public key from a privkey
        """
        if not os.path.isfile(key_file):
            return None
        command_params = [
            'openssl', 'pkey', '-pubout',
            '-outform', 'pem'
            '-passin', f'pass:{key_pass}'
            '-in', key_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if  process.returncode == 0 :
            return stdout.decode('utf-8').rstrip('\n')
        else:
            return None

    @staticmethod
    def get_subject_comma_separated_format(subj):
        """
        Get converted X509Name object to a comma separeted format
        ex: 'CN=test,ST=Tehran,emailAddress=test@test'
        """
        str_components = [(k.decode('utf-8')+ '=' +v.decode('utf-8')) for k,v in subj.get_components()]
        return ','.join(str_components)

    @staticmethod
    def get_cert_subject(cert_file):
        """
        Get subject from a cert file with custom comma separeted format
        """
        cert = None
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as err:
            return None
        return SslUtility.get_subject_comma_separated_format(cert.get_subject())

    @staticmethod
    def get_cert_issuer(cert_file):
        """
        Get issuer organization from a cert file in str format
        """
        cert = None
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as err:
            return None
        # base on fortinet only O or CN can display in issuer field
        for k,v in cert.get_issuer().get_components():
            if k.decode('utf-8') == 'O':
                return v.decode('utf-8')
        for k,v in cert.get_issuer().get_components():
            if k.decode('utf-8') == 'CN':
                return v.decode('utf-8')
        return ''

    @staticmethod
    def get_random_string(length):
        import random
        import string
        letters = string.ascii_letters
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str
    
    @staticmethod
    def is_encrypted_key(key_file):
        # if key unlocked with fake_pass then key isn't encrypted
        fake_pass = SslUtility.get_random_string(50)
        try:
            load_privatekey(FILETYPE_PEM, open(key_file).read(), bytes(fake_pass, 'utf-8'))
        except Exception as e:
            return True
        return False

    @staticmethod
    def is_pkey_pass_correct(key_file, key_pass):
        if key_pass == '':
            return False
        try:
            load_privatekey(FILETYPE_PEM, open(key_file).read(), bytes(key_pass, 'utf-8'))
        except Exception as e:
            return False
        return True

    @staticmethod
    def convert_cert_date_to_local_datetime(cert_asn1date):
        cert_date = cert_asn1date.decode('utf-8')[:-1]
        dt = datetime.strptime(cert_date,'%Y%m%d%H%M%S')
        from_zone = tz.gettz('GMT')
        to_zone = tz.gettz('Asia/Tehran')
        dt = dt.replace(tzinfo=from_zone)
        dt = dt.astimezone(to_zone)
        return dt

    @staticmethod
    def convert_openssl_date_to_local_datetime(openssl_date_format):
        # example openssl date format: 'Nov 30 20:20:05 2021 GMT'
        try:
            dt = datetime.strptime(openssl_date_format, '%b %d %H:%M:%S %Y GMT')
        except Exception as err:
            return None
        from_zone = tz.gettz('GMT')
        to_zone = tz.gettz('Asia/Tehran')
        dt = dt.replace(tzinfo=from_zone)
        dt = dt.astimezone(to_zone)
        return dt

    @staticmethod
    def get_cert_expire_date(cert_file):
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as err:
            return '0'
        enddate = cert.get_notAfter()
        dt = SslUtility.convert_cert_date_to_local_datetime(enddate)
        return dt.strftime('%Y/%m/%d %H:%M:%S')

    @staticmethod
    def get_cert_expire_date_asn1_format(cert_file):
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as err:
            return '0'
        enddate_asn1format = cert.get_notAfter()
        return enddate_asn1format.decode('utf-8')

    @staticmethod
    def get_cert_serial_number(cert_file):
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as err:
            return 0
        return cert.get_serial_number()

    @staticmethod
    def get_validaty_days(cert_file):
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as err:
            return 0
        start_dt = SslUtility.convert_cert_date_to_local_datetime(cert.get_notBefore())
        end_dt = SslUtility.convert_cert_date_to_local_datetime(cert.get_notAfter())
        delta_dt = end_dt - start_dt
        return abs(delta_dt.days)

    @staticmethod
    def is_csr_file(csr_file):
        try:
            load_certificate_request(FILETYPE_PEM, open(csr_file).read())
        except Exception as e:
            return False
        return True

    @staticmethod
    def is_cert_file(cert_file):
        try:
            load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as e:
            return False
        return True

    @staticmethod
    def is_crl_file(crl_file):
        try:
            load_crl(FILETYPE_PEM, open(crl_file).read())
        except Exception as e:
            return False
        return True

    @staticmethod
    def is_CA_cert(cert_file):
        try:
            cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        except Exception as e:
            return False
        ca_true = False
        for ext in range(cert.get_extension_count()):
            if str(cert.get_extension(ext)) == 'CA:TRUE':
                ca_true = False
        if not ca_true:
            return False
        for i in range(cert.get_extension_count()):
            if 'Certificate Sign' in str(cert.get_extension(i)):
                return True
        return False

    @staticmethod
    def get_subject_hash_cert(cert_file):
        command_params = [
            'openssl', 'x509',
            '-subject_hash', '-noout',
            '-in', cert_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout.decode('utf-8').rstrip('\n')
        return None

    @staticmethod
    def get_issuer_hash_crl(crl_file):
        command_params = [
            'openssl', 'crl',
            '-hash', '-noout',
            '-in', crl_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout.decode('utf-8').rstrip('\n')
        return None

    @staticmethod
    def get_crl_info(crl_file):
        crl_info = {}
        try:
            load_crl(FILETYPE_PEM, open(crl_file).read())
        except Exception as e:
            return crl_info
        # TODO:
        return crl_info

    @staticmethod
    def crl_verify(crl_file):
        command_params = [
            'openssl', 'crl',
            '-CApath', constant.PKI_TRUSTED_DIR,
            '-in', crl_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return True
        return False

    @staticmethod
    def check_cert_signed_by_ca(cert_file, ca_file):
        command_params = [
            'openssl', 'verify',
            '-CAfile', ca_file,
            cert_file,
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return True
        return False

    @staticmethod
    def is_p12_file(p12_file):
        try:
            p12 = load_pkcs12(open(p12_file, 'rb').read())
        except Exception as e:
            for arg in e.args:
                for errs in arg:
                    if 'PKCS12_parse' not in errs:
                        return False
            return True    
        else:
            return True

    @staticmethod
    def is_correct_p12_pass(p12_file, p12_pass):
        try:
            p12 = load_pkcs12(open(p12_file, 'rb').read(), bytes(p12_pass, 'utf-8'))
        except Exception as e:
            for arg in e.args:
                for errs in arg:
                    if 'PKCS12_parse' in errs:
                        return False
        else:
            return True

    @staticmethod
    def parse_p12file(p12_file, p12_pass, export_cert_path, export_key_path):
        if not SslUtility.is_correct_p12_pass(p12_file, p12_pass):
            return False
        
        # get key file
        command_params = [
            'openssl', 'pkcs12',
            '-in', p12_file,
            '-passin', f'pass:{p12_pass}',
            '-passout', f'pass:{p12_pass}',
            '-nocerts',
            '-out', export_key_path + '.temp'
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            return False
        
        # get cert file
        command_params = [
            'openssl', 'pkcs12',
            '-in', p12_file,
            '-passin', f'pass:{p12_pass}',
            '-passout', f'pass:{p12_pass}',
            '-clcerts', '-nokeys',
            '-out', export_cert_path
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            return False
        
        # change key pass to dafault pass
        command_params = [
            'openssl', 'pkey',
            '-in', export_key_path + '.temp',
            '-passin', f'pass:{p12_pass}',
            '-aes256',
            '-passout', f'pass:{constant.PRIVKEY_DEFAULT_PASS}',
            '-out', export_key_path
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            return False
        
        return True

    @staticmethod
    def create_encrypted_key(key_file, encrypted_key, key_pass):
        command_params = [
            'openssl', 'pkey',
            '-in', key_file,
            '-aes256',
            '-passout', f'pass:{key_pass}',
            '-out', encrypted_key
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return encrypted_key
        return None


    class CertUtils:

        def __init__(self, cert_file):
            self.cert_file = cert_file
            try:
                self.cert = load_certificate(FILETYPE_PEM, open(self.cert_file).read())
            except Exception as e:
                self.cert = None

        def is_cert_file(self):
            return self.cert is not None

        def get_version(self):
            if not self.is_cert_file():
                return ''
            return self.cert.get_version() + 1

        def get_serial_number(self):
            if not self.is_cert_file():
                return 0
            return self.cert.get_serial_number()

        def get_subject(self):
            if not self.is_cert_file():
                return {}
            dn = {}
            for k, v in self.cert.get_subject().get_components():
                dn[k.decode('utf-8')] = v.decode('utf-8')
            return dn

        def get_issuer(self):
            if not self.is_cert_file():
                return {}
            dn = {}
            for k, v in self.cert.get_issuer().get_components():
                dn[k.decode('utf-8')] = v.decode('utf-8')
            return dn

        def get_not_before_date(self):
            if not self.is_cert_file():
                return ''
            not_before = self.cert.get_notBefore()
            dt = SslUtility.convert_cert_date_to_local_datetime(not_before)
            return dt.strftime('%Y/%m/%d %H:%M:%S')

        def get_not_after_date(self):
            if not self.is_cert_file():
                return ''
            not_after = self.cert.get_notAfter()
            dt = SslUtility.convert_cert_date_to_local_datetime(not_after)
            return dt.strftime('%Y/%m/%d %H:%M:%S')

        def get_md5_fingerprint(self):
            if not self.is_cert_file():
                return ''
            fingerprint = self.cert.digest('md5').decode('utf-8')
            return fingerprint

        def get_extensions(self):
            if not self.is_cert_file():
                return {}
            extensions = {}
            for index in range(self.cert.get_extension_count()):
                ext_name = self.cert.get_extension(index).get_short_name().decode('utf-8')
                ext_value = str(self.cert.get_extension(index))
                is_critical = self.cert.get_extension(index).get_critical()
                extensions[ext_name] = {'critical': is_critical, 'ext_value': ext_value}
            return extensions


    class CrlUtils:

        def __init__(self, crl_file):
            self.crl_file = crl_file
            try:
                self.crl = load_crl(FILETYPE_PEM, open(self.crl_file).read())
            except Exception as e:
                self.crl = None

        def is_crl_file(self):
            return self.crl is not None

        def get_issuer_short_format(self):
            if not self.is_crl_file():
                return ''
            for k,v in self.crl.get_issuer().get_components():
                if k.decode('utf-8') == 'O':
                    return v.decode('utf-8')
            for k,v in self.crl.get_issuer().get_components():
                if k.decode('utf-8') == 'CN':
                    return v.decode('utf-8')
            return ''

        def get_issuer_dn(self):
            if not self.is_crl_file():
                return ''
            return SslUtility.get_subject_comma_separated_format(self.crl.get_issuer())

        def get_revoked_certs_serial(self):
            if not self.is_crl_file():
                return ''
            serials = []
            for revoked in self.crl.get_revoked():
                serials.append(revoked.get_serial())
            return serials

        def get_issuer_hash(self):
            if not self.is_crl_file():
                return ''
            command_params = [
                'openssl', 'crl',
                '-hash', '-noout',
                '-in', self.crl_file,
            ]
            process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                return stdout.decode('utf-8').rstrip('\n')
            return None

        def get_crl_number(self):
            if not self.is_crl_file():
                return ''
            command_params = [
                'openssl', 'crl',
                '-crlnumber', '-noout',
                '-in', self.crl_file,
            ]
            process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                return stdout.decode('utf-8').rstrip('\n').split('=')[1]
            return None

        def get_last_update(self):
            if not self.is_crl_file():
                return ''
            command_params = [
                'openssl', 'crl',
                '-lastupdate', '-noout',
                '-in', self.crl_file,
            ]
            process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                lastupdate = stdout.decode('utf-8').rstrip('\n').split('=')[1]
                dt = SslUtility.convert_openssl_date_to_local_datetime(lastupdate)
                return dt.strftime('%Y/%m/%d %H:%M:%S')
            return None

        def get_next_update(self):
            if not self.is_crl_file():
                return ''
            # TODO: convert return date to custom format
            command_params = [
                'openssl', 'crl',
                '-nextupdate', '-noout',
                '-in', self.crl_file,
            ]
            process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                nextupdate = stdout.decode('utf-8').rstrip('\n').split('=')[1]
                dt = SslUtility.convert_openssl_date_to_local_datetime(nextupdate)
                return dt.strftime('%Y/%m/%d %H:%M:%S')
            return None
