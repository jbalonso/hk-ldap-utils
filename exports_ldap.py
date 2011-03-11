#!/usr/bin/env python
import ldap
import re

class config:
        LDAP_CONF = '/etc/ldap.conf'
        LDAP_SECRET = '/etc/ldap.secret'
        TARGET_DEFAULT = '/tmp/exports'

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

def find_points(conf, con):
        base = conf['exports_base'][0]
        host = conf['exports_host'][0]
        scope = ldap.SCOPE_ONELEVEL
        filter = '(&(objectClass=exportsPoint)(|(!(exportsHost=*))(exportsHost=%s)))' % host
        entries = con.search_s(base, scope, filter)
        entries = dict((entry[0],entry[1]) for entry in entries)
        return entries

def find_clients(con, point_dn):
        base = point_dn
        scope = ldap.SCOPE_ONELEVEL
        filter = '(objectClass=exportsClient)'
        entries = con.search_s(base, scope, filter)
        entries = dict((entry[0],entry[1]) for entry in entries)
        return entries

def format_entry(con, dn, entry):
        # Get clients
        clients = find_clients(con, dn)

        # Construct clients string
        client_str = ''
        for client in clients.values():
                client_str += client['exportsClientPattern'][0] + '(' + ','.join(client['exportsOption']) + ') '

        return entry['exportsPath'][0] + '\t' + client_str

def get_entries(conf, con):
        text = [format_entry(con, dn, ent) for dn, ent in find_points(conf, con).iteritems()]
        return text

def write_target(conf, entries):
        fn = conf.get('exports_target', config.TARGET_DEFAULT)
        assert len(entries) > 0, 'New configuration must have at least one entry.'
        out_file = open( fn, 'w' )
        out_file.writelines(['%s\n' % ent for ent in entries])

if __name__ == '__main__':
        conf = read_conf()
        con = connect(conf)
        entries = get_entries(conf, con)
        con.unbind_s()
        write_target(conf, entries)
