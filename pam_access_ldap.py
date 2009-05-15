
import ldap
import re

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
                        con.simple_bind_s(*creds)
                        return con
                except:
                        pass
        assert False, 'Failed to connect to LDAP server.'

def find_entries(conf, con):
        base = conf['pam_access_base'][0]
        host = conf['pam_access_host'][0]
        scope = ldap.SCOPE_ONELEVEL
        filter = '(&(objectClass=pamAccessRecord)(|(!(pamAccessHost=*))(pamAccessHost=%s)))' % host
        entries = con.search_s(base, scope, '(objectClass=pamAccessRecord)')
        entries = [entry[1] for entry in entries]
        entries.sort(key=lambda x: x['pamAccessSequence'][0])
        return entries

def format_entry(entry):
        if entry['pamAccessGrant'][0].upper() == 'TRUE':
                grant = '+'
        else:
                grant = '-'

        names = []
        for dn in entry.get('pamAccessEntity', ['cn=ALL']):
                part = dn.split(',',1)[0]
                names.append( part.split('=',1)[1] )

        origins = entry['pamAccessOrigins']

        return '%s:%s:%s' % (grant, ' '.join(names), ' '.join(origins))

def get_entries():
        conf = read_conf()
        con = connect(conf)
        text = [format_entry(ent) for ent in find_entries(conf, con)]
        for txt in text: print txt
        con.unbind_s()
