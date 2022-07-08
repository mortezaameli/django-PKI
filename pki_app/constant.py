import os

PKI_CA_CONF = os.getcwd() + '/pki-ca.cnf'
PKI_VPN_CONF = os.getcwd() + '/pki-vpn.cnf'
PKI_CA_DB_DIR = os.getcwd() + '/pki_app/pki_db/ca-db/'
PKI_CSR_DIR = os.getcwd() + '/pki_app/pki_db/csr/'
PKI_KEY_DIR = os.getcwd() + '/pki_app/pki_db/privkey/'
PKI_CRL_DIR = os.getcwd() + '/pki_app/pki_db/crl/'
PKI_TRUSTED_DIR = os.getcwd() + '/pki_app/pki_db/trusted/'
PKI_CERT_DIR = os.getcwd() + '/pki_app/pki_db/cert/'
PKI_TMP_DIR = os.getcwd() + '/pki_app/pki_db/tmp/'

PKI_EXTESION_VPN_CERT = 'vpn_cert'
PKI_EXTESION_V3_INTERMEDIATE_CA = 'v3_intermediate_ca'

PRIVKEY_DEFAULT_PASS = '!p88co89el-2(_bus04uk#dfdri(8pt(ot7iu&-l0sqsm9(0'

VALID_STATUS = 'V'
REVOKED_STATUS = 'R'
EXPIRED_STATUS = 'E'

CERT_CATEGORIES = ['Local-CA', 'Local-Cert', 'Remote-CA', 'Remote-Cert']
CATEGORY_LOCAL_CA = 'Local-CA'
CATEGORY_LOCAL_CERT = 'Local-Cert'
CATEGORY_REMOTE_CA = 'Remote-CA'
CATEGORY_REMOTE_CERT = 'Remote-Cert'

TYPE_PRIVKEY = 'privkey'
TYPE_CERT = 'cert'
TYPE_CSR = 'csr'

DIGETS_ALGO = 'sha256'

SUBJECT_ID_TYPES = ['Host IP', 'Domain Name', 'E-Mail']
HOST_IP_TYPE = 'Host IP'
DOMAIN_NAME_TYPE = 'Domain Name'
EMAIL_TYPE = 'E-Mail'

KEY_TYPES = ['RSA', 'EC']
RSA_KEY = 'RSA'
EC_KEY = 'EC'
RSA_KEY_SIZE = [512, 1024, 1536, 2048, 4096]
EC_KEY_SIZE = [256, 384, 521] # 521 is correct in ec key(no 512)

# List of Country Codes
COUNTRY_CODES = {
    'AF': 'AFGHANISTAN',
    'AX': 'ALAND ISLANDS',
    'AL': 'ALBANIA',
    'DZ': 'ALGERIA',
    'AS': 'AMERICAN SAMOA',
    'AD': 'ANDORRA',
    'AO': 'ANGOLA',
    'AI': 'ANGUILLA',
    'AQ': 'ANTARCTICA',
    'AG': 'ANTIGUA AND BARBUDA',
    'AR': 'ARGENTINA',
    'AM': 'ARMENIA',
    'AW': 'ARUBA',
    'AU': 'AUSTRALIA',
    'AT': 'AUSTRIA',
    'AZ': 'AZERBAIJAN',
    'BS': 'BAHAMAS',
    'BH': 'BAHRAIN',
    'BD': 'BANGLADESH',
    'BB': 'BARBADOS',
    'BY': 'BELARUS',
    'BE': 'BELGIUM',
    'BZ': 'BELIZE',
    'BJ': 'BENIN',
    'BM': 'BERMUDA',
    'BT': 'BHUTAN',
    'BO': 'BOLIVIA, PLURINATIONAL STATE OF',
    'BQ': 'BONAIRE, SINT EUSTATIUS AND SABA',
    'BA': 'BOSNIA AND HERZEGOVINA',
    'BW': 'BOTSWANA',
    'BV': 'BOUVET ISLAND',
    'BR': 'BRAZIL',
    'IO': 'BRITISH INDIAN OCEAN TERRITORY',
    'BN': 'BRUNEI DARUSSALAM',
    'BG': 'BULGARIA',
    'BF': 'BURKINA FASO',
    'BI': 'BURUNDI',
    'KH': 'CAMBODIA',
    'CM': 'CAMEROON',
    'CA': 'CANADA',
    'CV': 'CAPE VERDE',
    'KY': 'CAYMAN ISLANDS',
    'CF': 'CENTRAL AFRICAN REPUBLIC',
    'TD': 'CHAD',
    'CL': 'CHILE',
    'CN': 'CHINA',
    'CX': 'CHRISTMAS ISLAND',
    'CC': 'COCOS (KEELING) ISLANDS',
    'CO': 'COLOMBIA',
    'KM': 'COMOROS',
    'CG': 'CONGO',
    'CD': 'CONGO, THE DEMOCRATIC REPUBLIC OF THE',
    'CK': 'COOK ISLANDS',
    'CR': 'COSTA RICA',
    'CI': 'CÔTE D’IVOIRE',
    'HR': 'CROATIA',
    'CU': 'CUBA',
    'CW': 'CURAÇAO',
    'CY': 'CYPRUS',
    'CZ': 'CZECH REPUBLIC',
    'DK': 'DENMARK',
    'DJ': 'DJIBOUTI',
    'DM': 'DOMINICA',
    'DO': 'DOMINICAN REPUBLIC',
    'EC': 'ECUADOR',
    'EG': 'EGYPT',
    'SV': 'EL SALVADOR',
    'GQ': 'EQUATORIAL GUINEA',
    'ER': 'ERITREA',
    'EE': 'ESTONIA',
    'ET': 'ETHIOPIA',
    'FK': 'FALKLAND ISLANDS (MALVINAS)',
    'FO': 'FAROE ISLANDS',
    'FJ': 'FIJI',
    'FI': 'FINLAND',
    'FR': 'FRANCE',
    'GF': 'FRENCH GUIANA',
    'PF': 'FRENCH POLYNESIA',
    'TF': 'FRENCH SOUTHERN TERRITORIES',
    'GA': 'GABON',
    'GM': 'GAMBIA',
    'GE': 'GEORGIA',
    'DE': 'GERMANY',
    'GH': 'GHANA',
    'GI': 'GIBRALTAR',
    'GR': 'GREECE',
    'GL': 'GREENLAND',
    'GD': 'GRENADA',
    'GP': 'GUADELOUPE',
    'GU': 'GUAM',
    'GT': 'GUATEMALA',
    'GG': 'GUERNSEY',
    'GN': 'GUINEA',
    'GW': 'GUINEA-BISSAU',
    'GY': 'GUYANA',
    'HT': 'HAITI',
    'HM': 'HEARD ISLAND AND MCDONALD ISLANDS',
    'VA': 'HOLY SEE (VATICAN CITY STATE)',
    'HN': 'HONDURAS',
    'HK': 'HONG KONG',
    'HU': 'HUNGARY',
    'IS': 'ICELAND',
    'IN': 'INDIA',
    'ID': 'INDONESIA',
    'IR': 'IRAN, ISLAMIC REPUBLIC OF',
    'IQ': 'IRAQ',
    'IE': 'IRELAND',
    'IM': 'ISLE OF MAN',
    'IL': 'ISRAEL',
    'IT': 'ITALY',
    'JM': 'JAMAICA',
    'JP': 'JAPAN',
    'JE': 'JERSEY',
    'JO': 'JORDAN',
    'KZ': 'KAZAKHSTAN',
    'KE': 'KENYA',
    'KI': 'KIRIBATI',
    'KP': 'KOREA, DEMOCRATIC PEOPLE’S REPUBLIC OF',
    'KR': 'KOREA, REPUBLIC OF',
    'KW': 'KUWAIT',
    'KG': 'KYRGYZSTAN',
    'LA': 'LAO PEOPLE’S DEMOCRATIC REPUBLIC',
    'LV': 'LATVIA',
    'LB': 'LEBANON',
    'LS': 'LESOTHO',
    'LR': 'LIBERIA',
    'LY': 'LIBYA',
    'LI': 'LIECHTENSTEIN',
    'LT': 'LITHUANIA',
    'LU': 'LUXEMBOURG',
    'MO': 'MACAO',
    'MK': 'MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF',
    'MG': 'MADAGASCAR',
    'MW': 'MALAWI',
    'MY': 'MALAYSIA',
    'MV': 'MALDIVES',
    'ML': 'MALI',
    'MT': 'MALTA',
    'MH': 'MARSHALL ISLANDS',
    'MQ': 'MARTINIQUE',
    'MR': 'MAURITANIA',
    'MU': 'MAURITIUS',
    'YT': 'MAYOTTE',
    'MX': 'MEXICO',
    'FM': 'MICRONESIA, FEDERATED STATES OF',
    'MD': 'MOLDOVA, REPUBLIC OF',
    'MC': 'MONACO',
    'MN': 'MONGOLIA',
    'ME': 'MONTENEGRO',
    'MS': 'MONTSERRAT',
    'MA': 'MOROCCO',
    'MZ': 'MOZAMBIQUE',
    'MM': 'MYANMAR',
    'NA': 'NAMIBIA',
    'NR': 'NAURU',
    'NP': 'NEPAL',
    'NL': 'NETHERLANDS',
    'NC': 'NEW CALEDONIA',
    'NZ': 'NEW ZEALAND',
    'NI': 'NICARAGUA',
    'NE': 'NIGER',
    'NG': 'NIGERIA',
    'NU': 'NIUE',
    'NF': 'NORFOLK ISLAND',
    'MP': 'NORTHERN MARIANA ISLANDS',
    'NO': 'NORWAY',
    'OM': 'OMAN',
    'PK': 'PAKISTAN',
    'PW': 'PALAU',
    'PS': 'PALESTINE, STATE OF',
    'PA': 'PANAMA',
    'PG': 'PAPUA NEW GUINEA',
    'PY': 'PARAGUAY',
    'PE': 'PERU',
    'PH': 'PHILIPPINES',
    'PN': 'PITCAIRN',
    'PL': 'POLAND',
    'PT': 'PORTUGAL',
    'PR': 'PUERTO RICO',
    'QA': 'QATAR',
    'RE': 'RÉUNION',
    'RO': 'ROMANIA',
    'RU': 'RUSSIAN FEDERATION',
    'RW': 'RWANDA',
    'BL': 'SAINT BARTHÉLEMY',
    'SH': 'SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA',
    'KN': 'SAINT KITTS AND NEVIS',
    'LC': 'SAINT LUCIA',
    'MF': 'SAINT MARTIN (FRENCH PART)',
    'PM': 'SAINT PIERRE AND MIQUELON',
    'VC': 'SAINT VINCENT AND THE GRENADINES',
    'WS': 'SAMOA',
    'SM': 'SAN MARINO',
    'ST': 'SAO TOME AND PRINCIPE',
    'SA': 'SAUDI ARABIA',
    'SN': 'SENEGAL',
    'RS': 'SERBIA',
    'SC': 'SEYCHELLES',
    'SL': 'SIERRA LEONE',
    'SG': 'SINGAPORE',
    'SX': 'SINT MAARTEN (DUTCH PART)',
    'SK': 'SLOVAKIA',
    'SI': 'SLOVENIA',
    'SB': 'SOLOMON ISLANDS',
    'SO': 'SOMALIA',
    'ZA': 'SOUTH AFRICA',
    'GS': 'SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS',
    'SS': 'SOUTH SUDAN',
    'ES': 'SPAIN',
    'LK': 'SRI LANKA',
    'SD': 'SUDAN',
    'SR': 'SURINAME',
    'SJ': 'SVALBARD AND JAN MAYEN',
    'SZ': 'SWAZILAND',
    'SE': 'SWEDEN',
    'CH': 'SWITZERLAND',
    'SY': 'SYRIAN ARAB REPUBLIC',
    'TW': 'TAIWAN, PROVINCE OF CHINA',
    'TJ': 'TAJIKISTAN',
    'TZ': 'TANZANIA, UNITED REPUBLIC OF',
    'TH': 'THAILAND',
    'TL': 'TIMOR-LESTE',
    'TG': 'TOGO',
    'TK': 'TOKELAU',
    'TO': 'TONGA',
    'TT': 'TRINIDAD AND TOBAGO',
    'TN': 'TUNISIA',
    'TR': 'TURKEY',
    'TM': 'TURKMENISTAN',
    'TC': 'TURKS AND CAICOS ISLANDS',
    'TV': 'TUVALU',
    'UG': 'UGANDA',
    'UA': 'UKRAINE',
    'AE': 'UNITED ARAB EMIRATES',
    'GB': 'UNITED KINGDOM',
    'US': 'UNITED STATES',
    'UM': 'UNITED STATES MINOR OUTLYING ISLANDS',
    'UY': 'URUGUAY',
    'UZ': 'UZBEKISTAN',
    'VU': 'VANUATU',
    'VE': 'VENEZUELA, BOLIVARIAN REPUBLIC OF',
    'VN': 'VIET NAM',
    'VG': 'VIRGIN ISLANDS, BRITISH',
    'VI': 'VIRGIN ISLANDS, U.S.',
    'WF': 'WALLIS AND FUTUNA',
    'EH': 'WESTERN SAHARA',
    'YE': 'YEMEN',
    'ZM': 'ZAMBIA',
    'ZW': 'ZIMBABWE'
}
