from rest_framework import serializers
from rest_framework.validators import ValidationError
from pki_app import models
from pki_app.validators import PkiValidators


class SubjectInfoSeriaserlizer(serializers.Serializer):
    id_type = serializers.CharField(required=True)
    subject = serializers.CharField(required=True, max_length=64)
    organization = serializers.CharField(required=False, max_length=64)
    organization_unit = serializers.ListField(
        child = serializers.CharField(required=False, max_length=64)
    )
    locality = serializers.CharField(required=False, max_length=128)
    state = serializers.CharField(required=False, max_length=128)
    country = serializers.CharField(required=False)
    email = serializers.CharField(required=False, max_length=64)


class PkiCreateSelfsignSerializer(serializers.Serializer):
    name = serializers.CharField(required=True, max_length=35)
    subject_info = SubjectInfoSeriaserlizer(source='*')
    key_type = serializers.CharField(required=True)
    key_size = serializers.IntegerField(required=True)
    validity_days = serializers.IntegerField(required=True, min_value=1, max_value=3650)
    privkey_pass = serializers.CharField(required=False, min_length=4, max_length=1023)

    def validate(self, data):
        ok, err = PkiValidators.check_subj_type_and_value(data.get('id_type'), data.get('subject'))
        if not ok:
            raise serializers.ValidationError(err)
        ok, err = PkiValidators.check_country(data.get('country'))
        if not ok:
            raise serializers.ValidationError(err)
        ok, err = PkiValidators.check_email(data.get('email'))
        if not ok:
            raise serializers.ValidationError(err)
        ok, err = PkiValidators.check_key_type_size(data.get('key_type'), data.get('key_size'))
        if not ok:
            raise serializers.ValidationError(err)
        return data


class PkiCreateCsrSerializer(serializers.Serializer):
    # id = serializers.IntegerField(required=False)
    name = serializers.CharField(required=True, max_length=35)
    subject_info = SubjectInfoSeriaserlizer(source='*')
    key_type = serializers.CharField(required=True)
    key_size = serializers.IntegerField(required=True)
    privkey_pass = serializers.CharField(required=False, min_length=4, max_length=1023)

    def validate(self, data):
        ok, err = PkiValidators.check_subj_type_and_value(data.get('id_type'), data.get('subject'))
        if not ok:
            raise serializers.ValidationError(err)
        ok, err = PkiValidators.check_country(data.get('country'))
        if not ok:
            raise serializers.ValidationError(err)
        ok, err = PkiValidators.check_email(data.get('email'))
        if not ok:
            raise serializers.ValidationError(err)
        ok, err = PkiValidators.check_key_type_size(data.get('key_type'), data.get('key_size'))
        if not ok:
            raise serializers.ValidationError(err)
        return data


class PkiSignCsrSerializer(serializers.Serializer):
    category = serializers.CharField(required=True)
    name = serializers.CharField(required=True, max_length=35)
    validity_days = serializers.IntegerField(required=True, min_value=1, max_value=3650)
    can_sign = serializers.BooleanField(required=False, default=False)
    ca_privkey_pass = serializers.CharField(required=False, min_length=4, max_length=1023)

    def validate(self, data):
        ok, err = PkiValidators.check_cert_category(data.get('category'))
        if not ok:
            raise serializers.ValidationError(err)
        return data


class PkiCreateCrlSerializer(serializers.Serializer):
    # TODO: validity_days must be implement later or not?
    # validity_days = serializers.IntegerField()
    ca_privkey_pass = serializers.CharField(required=False, min_length=4, max_length=1023)


class PkiDownloadP12Serializer(serializers.Serializer):
    name = serializers.CharField(required=True, max_length=35)
    p12pass = serializers.CharField(required=True, max_length=2048)
    privkey_pass = serializers.CharField(required=False, min_length=4, max_length=1023)


class PkiRevokeCertSerializer(serializers.Serializer):
    category = serializers.CharField(required=True)
    name = serializers.CharField(required=True, max_length=35)
    ca_privkey_pass = serializers.CharField(required=False, min_length=4, max_length=1023)

    def validate(self, data):
        ok, err = PkiValidators.check_cert_category(data.get('category'))
        if not ok:
            raise serializers.ValidationError(err)
        return data
