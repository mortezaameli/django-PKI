from django.urls import path
from pki_app import views


urlpatterns = [
    ### -------- List of valid value for fields -------- ###
    path('valid-fields/key/', views.PkiValidKeyFieldsView.as_view(), name='valid_key_algoritm_list'),
    path('valid-fields/cert-category/', views.PkiValidCertCategoriesView.as_view(), name='valid_cert_category_list'),

    ### -------- System operations -------- ###
    path('cert/local/selfsign/generate/', views.PkiSelfSignView.as_view(), name='generate_selfsign'),
    path('cert/local/issuer-ca/<str:name>/', views.PkiIssuerCaView.as_view(), name='set_issuer_ca'),
    path('cert/local/csr/generate/', views.PkiCsrView.as_view(), name='create_csr'),
    path('cert/csr/sign/', views.PkiSignCsrView.as_view(), name='sign_csr'),
    path('cert/local/cert/revoke/', views.PkiRevokeLocalCertView.as_view(), name='revoke_local_cert'),
    path('crl/generate/', views.PkiCreateCrlView.as_view(), name='generate_crl'),

    ### -------- Display detail and delete -------- ###
    path('certs/', views.PkiCertsListView.as_view(), name='certs_list'),
    path('cert/cert/<str:category>/<str:name>/', views.PkiCertView.as_view(), name='cert_detail_and_delete'),
    path('cert/local/issuer-ca/', views.PkiIssuerCaView.as_view(), name='issuer_ca_info'),
    path('crls/', views.PkiCrlsListView.as_view(), name='crls_list'),
    path('crl/<str:name>/', views.PkiCrlView.as_view(), name='crl_detail_and_delete'),

    ### -------- Import files -------- ###
    path('import/cert/remote/csr/', views.PkiImportRemoteCsrView.as_view(), name='import_remote_csr'),
    path('import/cert/local/cert/', views.PkiImportLocalCertView.as_view(), name='import_local_cert'),
    path('import/cert/remote/ca/', views.PkiImportRemoteCaView.as_view(), name='import_remote_ca'),
    path('import/crl/', views.PkiImportCrlView.as_view(), name='import_crl'),
    path('import/cert/local/p12/', views.PkiImportP12View.as_view(), name='import_p12'),
    path('import/cert/remote/cert/', views.PkiImportRemoteCertView.as_view(), name='import_remote_cert'),
    path('import/cert/local/cert-with-key/', views.PkiImportLocalCertWithKeyView.as_view(), name='import_local_cert_with_key'),

    ### -------- Download files -------- ###
    path('download/cert/cert/<str:category>/<str:name>/', views.PkiCertAndCsrFileDownloadView.as_view(), name='download_cert_or_csr_file'),
    path('download/cert/local/issuer-ca/', views.PkiIssuerCaFileDownloadView.as_view(), name='download_issuer_ca'),
    path('download/cert/local/p12/', views.PkiP12FileDownloaView.as_view(), name='download_p12'),
    path('download/crl/<str:name>/', views.PkiCrlFileDownloaView.as_view(), name='download_crl'),
]
