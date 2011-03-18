#!/usr/bin/env python
import ldap
import re
import os
from subprocess import Popen
from sys import argv
import time
import struct
import hmac
import hashlib
import base64

class config:
    LDAP_CONF = '/etc/ldap.conf'
    LDAP_SECRET = '/etc/ldap.secret'

def read_conf():
    ldap_conf = open(config.LDAP_CONF)
    comments = re.compile('#.*')
    conf = {}
    for line in ldap_conf:
        line = line.strip()
        line = comments.sub('', line)
        keyval = line.split(None,1)
        if len(keyval) > 0:
            key = keyval[0].lower()
            vals = keyval[1].split()
            conf[key] = vals
    return conf

def get_credentials(conf):
    ldap_secret = open(config.LDAP_SECRET)
    secret = ldap_secret.readline().strip()
    return conf['rootbinddn'][0], secret

def connect(conf):
    creds = get_credentials(conf)
    for uri in conf['uri']:
        try:
            con = ldap.initialize(uri)
            if conf.get('ssl',['on'])[0].lower() == 'start_tls':
                con.start_tls_s()
            con.simple_bind_s(*creds)
            return con
        except:
            pass
    assert False, 'Failed to connect to LDAP server.'

def find_records(conf, con):
    base = 'uid=%s,ou=People,dc=hackorp,dc=com' % argv[1] #conf['hk_otp_base'][0]
    scope = ldap.SCOPE_ONELEVEL
    filter = '(objectClass=hkAuthOTPBase)'
    entries = con.search_s(base, scope, filter)
    entries = dict((entry[0],entry[1]) for entry in entries)
    return entries

def generate_totp(otp_config):
    """This routine adapted from
       http://www.brool.com/index.php/using-google-authenticator-for-your-website"""
    assert 'hkAuthTOTP' in otp_config['objectClass'], 'generate_totp requires an hkAuthTOTP record'

    secretkey = otp_config['hkAuthSecret'][0]
    period = int(otp_config['hkAuthPeriod'][0])
    alg = otp_config['hkAuthAlgorithm'][0].lower()
    digits = int(otp_config['hkAuthDigits'][0])
    algmodule = lambda: hashlib.new(alg)

    tm = int(time.time() // period)

    # try one window behind and ahead as well
    codes = []
    for ix in [-1, 0, 1]:
        # convert timestamp to raw bytes
        b = struct.pack(">q", tm + ix)

        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secretkey, b, algmodule).digest()

        # extract 4 bytes from digest based on LSB
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset+4]

        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF
        code %= 10 ** digits
        code = ('%%0%dd' % digits) % code

        codes.append(code)

    return codes

def configure_authenticator(otp_config):
    assert 'hkAuthOTPBase' in otp_config['objectClass'], 'configure_authenticator requires an hkAuthOTPBase record'
    label = otp_config['hkAuthLabel'][0]
    digits = int(otp_config['hkAuthDigits'][0])
    secretkey = base64.b32encode(otp_config['hkAuthSecret'][0])
    alg = otp_config['hkAuthAlgorithm'][0].upper()

    params = {'digits': digits, 'secret': secretkey,
            'algorithm': alg}

    authtype = 'totp' if 'hkAuthTOTP' in otp_config['objectClass'] else 'hotp'
    if authtype == 'totp':
        params['period'] = int(otp_config['hkAuthPeriod'][0])
    elif authtype == 'hotp':
        params['counter'] = int(otp_config['hkAuthCounter'][0])

    uri = 'otpauth://%s/%s?' % (authtype, label)
    uri += '&'.join('%s=%s' % (k,v) for k, v in params.items())

    return uri

if __name__ == '__main__':
    conf = read_conf()
    con = connect(conf)
    records = find_records(conf, con)
    con.unbind_s()


