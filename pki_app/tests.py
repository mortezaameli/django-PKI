from django.test import TestCase
from django.test import Client
from django.urls import reverse
import json
from pki_app.ssl_utility import SslUtility
from . import constant
from . import models


class PkiTest(TestCase):

    def setUp(self):
        pass

    def test_create_selfsign(self):
        client = Client()
        python_dict= {
            "cert_name": "Root-CA",
            "key_type": "RSA",
            "key_size": 2048,
            "validity_days": 365,
            "subject_info": {
                "domain_name": "root_ca",
                "organization": "org1",
                "organization_unit": "org unit1",
                "locality": "Tehran",
                "state": "asia",
                "country": "IR",
                "email": "ca@ca"
            }
        }
        # TODO: first check have ca or not
        response = self.client.post(
            reverse('selfsign'),
            json.dumps(python_dict),
            content_type="application/json"
        )
        self.assertEqual(201, response.status_code)

    def test_key_cert_matched(self):
        selfsign_cert_path = constant.PKI_SIGNING_CERT_DIR + 'root_ca.crt'
        selfsign_key_path = constant.PKI_KEY_DIR + 'root_ca.key'
        selfsign_cert_pubkey = SslUtility.get_cert_pubkey(selfsign_cert_path)
        selfsign_key_pubkey = SslUtility.get_privkey_pubkey(selfsign_key_path, constant.PRIVKEY_DEFAULT_PASS)
        self.assertEqual(selfsign_cert_pubkey, selfsign_key_pubkey)

    def test_create_csr(self):
        client = Client()
        python_dict= {
            "csr_name": "client_A",
            "key_type": "RSA",
            "key_size": 1024,
            "is_ca": False,
            "subject_info": {
                "domain_name": "my_client",
                "organization": "org2",
                "organization_unit": "org unit 2",
                "locality": "Tehran",
                "state": "asia",
                "country": "IR",
                "email": "client@client"
            }
        }
        response = self.client.post(
            reverse('csr'),
            json.dumps(python_dict),
            content_type="application/json"
        )
        self.assertEqual(201, response.status_code)

    def test_csr_key_matched(self):
        csr_path = constant.PKI_CSR_DIR + 'my_client.csr'
        csr_key_path = constant.PKI_KEY_DIR + 'my_client.key'
        csr_pubkey = SslUtility.get_csr_pubkey(csr_path)
        csr_key_pubkey = SslUtility.get_privkey_pubkey(csr_key_path, constant.PRIVKEY_DEFAULT_PASS)
        self.assertEqual(csr_pubkey, csr_key_pubkey)
   
    def test_get_certs_list(self):
        client = Client()
        response = client.get(reverse('certs_list'))
        self.assertEqual(200, response.status_code)
    
    def tearDown(self):
        pass
        certs = models.PkiCertModel.objects.all()
        print(len(certs))
        # certs = models.PkiCertModel.objects.all()
        # for cert in certs:
        #     cert.delete()
        # csrs = models.PkiCsrModel.objects.all()
        # for csr in csrs:
        #     csr.delete()
