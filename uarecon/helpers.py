import os
import shutil
import tempfile
import subprocess


def uniq(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def format_exc(e):
    try:
        return f"{e.__class__.__name__}: {e}"
    except Exception:
        return repr(e)


def classify_error(e):
    msg = format_exc(e)
    low = msg.lower()

    keys = [
        "baduseraccessdenied",
        "badidentitytokenrejected",
        "badidentitytokeninvalid",
        "badcertificateuntrusted",
        "badcertificateuriinvalid",
        "badcertificateinvalid",
        "badsecuritypolicyrejected",
        "badsecuritymodeinsufficient",
        "badapplicationsignatureinvalid",
        "badsessionclosed",
        "badsessionidinvalid",
        "badsecurechannelclosed",
        "timeout",
    ]

    for k in keys:
        if k in low:
            return k

    return msg


def safe_disconnect(client):
    try:
        if client:
            client.disconnect()
    except Exception:
        pass


def sr(node):
    try:
        return node.read_value()
    except Exception:
        return None


def sn(node):
    try:
        return node.read_browse_name().Name
    except Exception:
        return "?"


def sc(node):
    try:
        return node.get_children()
    except Exception:
        return []


def generate_self_signed_cert(uri="urn:UARecon", out_dir=None):
    created_tmp = False
    if out_dir is None:
        out_dir = tempfile.mkdtemp(prefix="uarecon_")
        created_tmp = True

    cert_path = os.path.join(out_dir, "uarecon_cert.pem")
    key_path = os.path.join(out_dir, "uarecon_key.pem")
    cnf_path = os.path.join(out_dir, "uarecon.cnf")

    with open(cnf_path, "w") as f:
        f.write(
            f"""[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no
[req_dn]
CN = UARecon Scanner
O = Pentest
[v3_req]
subjectAltName = URI:{uri}
"""
        )

    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "1",
            "-nodes",
            "-config",
            cnf_path,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return None, None, cnf_path, out_dir, created_tmp

    return cert_path, key_path, cnf_path, out_dir, created_tmp


def generate_expired_cert(uri="urn:UARecon", out_dir=None):
    created_tmp = False
    if out_dir is None:
        out_dir = tempfile.mkdtemp(prefix="uarecon_")
        created_tmp = True

    cert_path = os.path.join(out_dir, "uarecon_expired_cert.pem")
    key_path = os.path.join(out_dir, "uarecon_expired_key.pem")
    cnf_path = os.path.join(out_dir, "uarecon_expired.cnf")

    with open(cnf_path, "w") as f:
        f.write(
            f"""[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no
[req_dn]
CN = UARecon Expired
O = Pentest
[v3_req]
subjectAltName = URI:{uri}
"""
        )

    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "0", "-nodes", "-config", cnf_path,
        ],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        return None, None, cnf_path, out_dir, created_tmp
    return cert_path, key_path, cnf_path, out_dir, created_tmp


def generate_wrong_uri_cert(out_dir=None):
    created_tmp = False
    if out_dir is None:
        out_dir = tempfile.mkdtemp(prefix="uarecon_")
        created_tmp = True

    cert_path = os.path.join(out_dir, "uarecon_wronguri_cert.pem")
    key_path = os.path.join(out_dir, "uarecon_wronguri_key.pem")
    cnf_path = os.path.join(out_dir, "uarecon_wronguri.cnf")

    with open(cnf_path, "w") as f:
        f.write(
            """[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no
[req_dn]
CN = UARecon WrongURI
O = Pentest
[v3_req]
subjectAltName = URI:urn:FAKE:InvalidApplication:NotReal
"""
        )

    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes", "-config", cnf_path,
        ],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        return None, None, cnf_path, out_dir, created_tmp
    return cert_path, key_path, cnf_path, out_dir, created_tmp


def cleanup_temp_artifacts(cert_path=None, key_path=None, cnf_path=None, out_dir=None, remove_dir=False):
    for p in [cert_path, key_path, cnf_path]:
        try:
            if p and os.path.isfile(p):
                os.unlink(p)
        except Exception:
            pass

    if remove_dir and out_dir:
        try:
            shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass
