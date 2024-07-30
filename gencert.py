#!/usr/bin/python

# Generate a key, self-signed certificate, and certificate request.
# Usage: gencert hostname [hostname...]
#
# When more than one hostname is provided, a SAN (Subject Alternate Name)
# certificate and request are generated.  The first hostname is used as the
# primary CN for the request.

import os,sys,stat
import subprocess
import tempfile
import argparse
import re

parser = argparse.ArgumentParser(
                    prog='gencert',
                    description='Generate a key, self-signed certificate, and certificate request.',usage="\n./gencert.py names\n./gencert.py -p ~/mycerts names")
parser.add_argument('names',nargs="+",help="Provide at least one hostname on the command line. Multiple space delimited hostnames may be provided to generate a SAN request.")
parser.add_argument('-p', '--path', required=False, help="Optional. Override Linux default output paths for generated files.")
args = parser.parse_args()

OPENSSL_CNF="""
[ req ]
default_bits        = 4096
default_md        = sha256
distinguished_name    = req_distinguished_name
prompt = no
%(req)s

[ req_distinguished_name ]
C=US
ST=California
L=Berkeley
O=University of California, Berkeley
%(cn)s

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true
subjectAltName = @alt_names

[ alt_names ]
%(alt)s
"""

SAN_REQ = """
x509_extensions    = v3_ca    # The extentions to add to the self signed cert
req_extensions = v3_req # The extensions to add to a certificate request
"""

def run(args):
    p = subprocess.Popen(args,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         close_fds=True)
    p.stdin.close()
    while True:
        o = p.stdout.read(1)
        if not o: break
        sys.stdout.write(o.decode())
        sys.stdout.flush()
    r = p.wait()
    if r:
        raise Exception('Error running %s'%args)

if __name__=="__main__":
    if len(args.names) == 1:
        names = [item for item in re.split(r'[ ,]+', args.names[0].strip()) if item]
    else:
        names = args.names

    if args.path:
        key_path = args.path
        crt_path = args.path
    else:
        key_path = '/etc/pki/tls/private'
        crt_path = '/etc/pki/tls/certs'

    params = dict(req='', dn='', alt='')
    if len(names)>1:
        # SAN
        san_names = ""
        for i,x in enumerate(names):
            san_names += f"DNS.{i} = {x}\n"
        params['req']=SAN_REQ
        params['alt']=san_names
        sanfn = '-san'
    else:
        sanfn = ''
    params['cn']='CN=%s'%names[0]
    keyfile = f"{key_path}/{names[0]}{sanfn}.key"
    crtfile = f"{crt_path}/{names[0]}{sanfn}.cert"
    csrfile = f"{crt_path}/{names[0]}{sanfn}.csr"
    (fh, cnffile) = tempfile.mkstemp()

    os.write(fh, str.encode(OPENSSL_CNF%params))
    os.close(fh)

    if os.path.exists(crtfile):
        print("Certificate file exists, aborting")
        print("  ", crtfile)
        sys.exit(1)

    if os.path.exists(csrfile):
        print("Certificate request file exists, aborting")
        print("  ", csrfile)
        sys.exit(1)

    if os.path.exists(keyfile):
        print("Key file exists, skipping key generation")
    else:
        run(['openssl', 'genrsa', '-out', keyfile, '4096'])
        os.chmod(keyfile, stat.S_IREAD )
    run(['openssl', 'req', '-config', cnffile, '-new', '-nodes', '-key', keyfile, '-out', csrfile])
    run(['openssl', 'req', '-config', cnffile, '-new', '-nodes', '-key', keyfile, '-out', crtfile, '-x509'])
    run(['openssl', 'req', '-in', csrfile, '-text'])
    
    os.unlink(cnffile)
