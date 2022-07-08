from . import constant

class PkiValidators():

    @staticmethod
    def check_cert_name(value):
        if len(value) > 35:
            return (False, 'Certificate name should not exceed 35 characters')
        return (True, '')


    @staticmethod
    def check_ip(value):
        import ipaddress
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return (False, 'IP format is incorrect')
        return (True, '')


    @staticmethod
    def check_subj_type_and_value(id_type, value):
        if id_type not in constant.SUBJECT_ID_TYPES:
            return (False, 'Subject ID type is incorrect')
        if id_type == constant.HOST_IP_TYPE:
            ok, err = PkiValidators.check_ip(value)
            if not ok:
                return (False, err)
        elif id_type == constant.DOMAIN_NAME_TYPE:
            if len(value) > 64:
                return (False, 'Domain name should not exceed 64 characters')
        elif id_type == constant.EMAIL_TYPE:
            ok, err = PkiValidators.check_email(value)
            if not ok:
                return (False, err)
        return (True, '')

    @staticmethod
    def check_country(value):
        if len(value) != 2:
            return (False, 'Country code must have 2 characters')
        if value not in constant.COUNTRY_CODES:
            return (False, 'Country code not exists in country list')
        return (True, '')

    @staticmethod
    def check_email(value):
        import re
        if len(value) > 64:
            return (False, 'Email should not exceed 64 characters')
        email_regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*$'
        if not re.search(email_regex, value):
            return (False, 'Email is incorrect')
        return (True, '')
    
    @staticmethod
    def check_key_type_size(key_type, key_size):
        if key_type not in constant.KEY_TYPES:
            return (False, 'Key Type is incorrect')
        if key_type == constant.RSA_KEY:
            if key_size not in constant.RSA_KEY_SIZE:
                return (False, 'RSA key size is incorrect')
            return (True, '')
        elif key_type == constant.EC_KEY:
            if key_size not in constant.EC_KEY_SIZE:
                return (False, 'EC key size is incorrect')
            return (True, '')
        return (True, '')
    
    @staticmethod
    def check_cert_category(value):
        if value not in constant.CERT_CATEGORIES:
            return (False, 'Category is incorrect')
        return (True, '')