#!/usr/bin/env python

from __future__ import print_function

from bs4 import BeautifulSoup as bs
from collections import OrderedDict
import json
import requests
import sys

IANA_URL = 'http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml'
OPENSSL_URL = 'https://raw.githubusercontent.com/openssl/openssl/master/include/openssl/tls1.h'

def get_hex_values():
    print('Retrieving IANA cipher List', file=sys.stderr)
    try:
        r = requests.get(IANA_URL)
        soup = bs(r.text, 'html.parser')\
            .select('table[id="table-tls-parameters-4"]')[0]\
            .find_all('tbody')[0]

        # Store all the ciphers away
        cipher_hex_values = OrderedDict()

        for row in soup.find_all('tr'):
            columns = [ x.string for x in row.find_all('td') ]

            # For now, we can ignore any IANA entries with '-' or '*' in them
            if '-' not in columns[0] and '*' not in columns[0]:
                cipher_hex_values[ columns[0] ] = {
                    'IANA': columns[1],
                    'OpenSSL': ''
                }

    except:
        print('Unable to retrieve or parse IANA cipher list', file=sys.stderr)

    print('Retrieving OpenSSL cipher list', file=sys.stderr)
    try:
        # OpenSSL splits up their code points and their text names for them
        openssl_hex_values = {}
        openssl_txt_values = {}

        r = requests.get(OPENSSL_URL)
        for line in r.text.split('\n'):
            if line.startswith('# define TLS1_CK'):
                cipher = line.split()[2].split('TLS1_CK_')[-1]
                hex = line.split()[3]
                code_point = '0x' + hex[6:8] + ',0x' + hex[8:10]

                # e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> 0x0C,0x2F
                openssl_hex_values[cipher] = code_point
            elif line.startswith('# define TLS1_TXT'):
                cipher = line.split()[2].split('TLS1_TXT_')[-1]
                text = line.split()[3][1:-1]

                # e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> ECDHE-RSA-AES128-GCM-SHA256
                openssl_txt_values[cipher] = text

        for key in openssl_hex_values.iterkeys():
            if openssl_hex_values[key] in cipher_hex_values:
                cipher_hex_values[openssl_hex_values[key]]['OpenSSL'] = openssl_txt_values[key]
            else:
                print('  Warning: code point {code_point} ({cipher}) not in IANA registry'.format(
                    code_point=openssl_hex_values[key], cipher=key
                ), file=sys.stderr)
    except:
        print('Unable to retrieve or parse OpenSSL cipher list', file=sys.stderr)

    print('\n', file=sys.stderr)
    return cipher_hex_values

def print_csv(data):
    print('codepoint,IANA,OpenSSL')
    for row in data:
        print('{},{}'.format(row.replace(',0x',''), ','.join(data[row].values())))

if __name__ == '__main__':
    output = get_hex_values()
    print_csv(output)
