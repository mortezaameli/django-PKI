from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (
        dump_certificate, dump_privatekey, dump_certificate_request,
        load_certificate, load_privatekey, load_certificate_request,
        PKey, X509, X509Req, X509Extension,
        TYPE_RSA, TYPE_DH, TYPE_EC, TYPE_DSA
    )
import os
from datetime import datetime
from . import constant
import re as regex
import subprocess
import hashlib
from .ssl_utility import SslUtility


class PkiOperations:
    """
    A Class that provide PKI operations with openssl
    """
    
    @staticmethod
    def make_subj(**dn):
        subj = ''
        if 'C' in dn:
            subj += '/C=' + dn['C']
        if 'ST' in dn:
            subj += '/ST=' + dn['ST']
        if 'L' in dn:
            subj += '/L=' + dn['L']
        if 'O' in dn:
            subj += '/O=' + dn['O']
        if 'OU' in dn:
            for ou in dn['OU']:
                subj += '/OU=' + ou
        if 'CN' in dn:
            subj += '/CN=' + dn['CN']
        if 'emailAddress' in dn:
            subj += '/emailAddress=' + dn['emailAddress']
        return subj
    

    @staticmethod
    def create_privkey(key_file_path, key_type, key_size, key_pass):
        """
        Create privkey
        """
        command_params = [
            'openssl', 'genpkey', '-aes256',
            '-algorithm', key_type,
            '-pass', f'pass:{key_pass}',
            '-out', key_file_path
        ]
        command_params.append('-pkeyopt')
        if key_type == 'RSA':
            command_params.append(f'rsa_keygen_bits:{key_size}')
        elif key_type == 'EC':
            command_params.append(f'ec_paramgen_curve:P-{key_size}')
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }
    

    @staticmethod
    def create_selfsign(selfsign_info:dict):
        """
        Create selfsign cert
        """
        create_privkey_info = PkiOperations.create_privkey(
            key_file_path=constant.PKI_KEY_DIR + selfsign_info.get('name') + '.key',
            key_type=selfsign_info.get('key_type'),
            key_size=selfsign_info.get('key_size'),
            key_pass=selfsign_info.get('privkey_pass')
        )
        if create_privkey_info.get('returncode') != 0:
            return {
                'stdout': create_privkey_info.get('stdout'),
                'stderr': create_privkey_info.get('stderr'),
                'returncode': create_privkey_info.get('returncode')
            }
        command_params = [
            'openssl', 'req',
            '-config', constant.PKI_CA_CONF,
            '-new', '-x509',
            '-days', str(selfsign_info.get('validity_days')),
            '-key', constant.PKI_KEY_DIR + selfsign_info.get("name") + '.key',
            '-passin', f'pass:{selfsign_info.get("privkey_pass")}',
            '-subj', PkiOperations.make_subj(
                C = selfsign_info.get('C'),
                ST = selfsign_info.get('ST'),
                L = selfsign_info.get('L'),
                O = selfsign_info.get('O'),
                OU = selfsign_info.get('OU'),
                CN = selfsign_info.get('CN'),
                emailAddress = selfsign_info.get('emailAddress')
            ),
            '-out', constant.PKI_CERT_DIR + selfsign_info.get("name") + '.cert',
            '-sha256'
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }
    

    @staticmethod
    def create_csr(csr_info:dict):
        """
        Create csr
        """
        create_privkey_info = PkiOperations.create_privkey(
            key_file_path=constant.PKI_KEY_DIR + csr_info.get('name') + '.key',
            key_type=csr_info.get('key_type'),
            key_size=csr_info.get('key_size'),
            key_pass=csr_info.get('privkey_pass')
        )
        if create_privkey_info.get('returncode') != 0:
            return {
                'stdout': create_privkey_info.get('stdout'),
                'stderr': create_privkey_info.get('stderr'),
                'returncode': create_privkey_info.get('returncode')
            }
        command_params = [
            'openssl', 'req', '-new',
            '-config', constant.PKI_VPN_CONF,
            '-key', constant.PKI_KEY_DIR + csr_info.get("name") + '.key',
            '-passin', f'pass:{csr_info.get("privkey_pass")}',
            '-subj', PkiOperations.make_subj(
                C = csr_info.get('C'),
                ST = csr_info.get('ST'),
                L = csr_info.get('L'),
                O = csr_info.get('O'),
                OU = csr_info.get('OU'),
                CN = csr_info.get('CN'),
                emailAddress = csr_info.get('emailAddress')
            ),
            '-out', constant.PKI_CSR_DIR + csr_info.get('name') + '.csr',
            '-sha256'
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }
    

    @staticmethod
    def sign_csr(ca_info:dict, new_cert_info:dict):
        """
        Sign csr with ca cert
        """
        if new_cert_info.get('can_sign') == True:
            extensions = constant.PKI_EXTESION_V3_INTERMEDIATE_CA
        else:
            extensions = constant.PKI_EXTESION_VPN_CERT
        command_params = [
            'openssl', 'ca',
            '-config', constant.PKI_CA_CONF,
            '-extensions', extensions,
            '-days', str(new_cert_info.get('validity_days')),
            '-in', new_cert_info.get('csr_file'),
            '-keyfile', ca_info.get('key_file'),
            '-cert', ca_info.get('cert_file'),
            '-out', constant.PKI_CERT_DIR + new_cert_info.get('name') + '.cert',
            '-outdir', constant.PKI_TMP_DIR,
            '-md', 'sha256',
            '-passin', f'pass:{ca_info.get("ca_privkey_pass")}',
            '-batch'
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }
    

    @staticmethod
    def revoke_cert(ca_info:dict, cert_info:dict):
        """
        Revoke cert with ca cert
        """
        command_params = [
            'openssl', 'ca',
            '-config', constant.PKI_CA_CONF,
            '-revoke', cert_info.get('cert_file'),
            '-keyfile', ca_info.get('key_file'),
            '-cert', ca_info.get('cert_file'),
            '-passin', f'pass:{ca_info.get("ca_privkey_pass")}'
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }


    @staticmethod
    def create_crl(ca_info:dict):
        """
        generate crl
        """
        command_params = [
            'openssl', 'ca', '-gencrl',
            '-config', constant.PKI_CA_CONF,
            '-crldays', str(ca_info.get('validity_days')),
            '-keyfile', ca_info.get('key_file'),
            '-cert', ca_info.get('cert_file'),
            '-out', constant.PKI_TRUSTED_DIR + ca_info.get('name') + '.crl',
            '-passin', f'pass:{ca_info.get("ca_privkey_pass")}',
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }
    

    @staticmethod
    def create_p12(p12_info:dict):
        command_params = [
            'openssl', 'pkcs12', '-export',
            '-out', p12_info.get('p12_file'),
            '-in', p12_info.get('cert_file'),
            '-inkey', p12_info.get('key_file'),
            '-passin', f'pass:{p12_info.get("privkey_pass")}',
            '-passout', f'pass:{p12_info.get("p12pass")}',
        ]
        process = subprocess.Popen(command_params,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {
            'stdout': stdout.decode('utf-8'),
            'stderr': stderr.decode('utf-8'),
            'returncode': process.returncode
        }


    @staticmethod
    def get_subject_str(subj):
        """
        Get converted X509Name object to a string we need
        ex: 'CN=test,ST=Tehran,emailAddress=test@test'
        """
        subj_str = ''
        for k, v in subj.get_components():
            subj_str += k.decode('utf-8') + '=' + v.decode('utf-8') + ','
        return subj_str[:-1]


    @staticmethod
    def get_cert_subject_str(cert_file):
        """
        Get subject object from a cert file
        """
        cert = load_certificate(FILETYPE_PEM, open(cert_file).read())
        return PkiOperations.get_subject_str(cert.get_subject())


    @staticmethod
    def get_csr_subject_str(csr_file):
        """
        Get subject object from a csr file
        """
        req = load_certificate_request(FILETYPE_PEM, open(csr_file).read())
        return PkiOperations.get_subject_str(req.get_subject())
