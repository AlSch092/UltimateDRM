#!/usr/bin/env python3
import json, argparse, base64, os, datetime as dt, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_json(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))

def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def main():
    ap = argparse.ArgumentParser(description="UltimateDRM license signer (ES256)")
    ap.add_argument("--priv", required=True, help="EC P-256 private key PEM (vendor)")
    ap.add_argument("--org", required=True)
    ap.add_argument("--plan", required=True, choices=["edu-floating","named-device","site"])
    ap.add_argument("--seats", type=int, default=None, help="None for site")
    ap.add_argument("--days", type=int, default=365, help="Validity days")
    ap.add_argument("--features", nargs="*", default=["rules-signing","gpu-gate","webhook"])
    ap.add_argument("--key-id", default="v1")
    args = ap.parse_args()

    now = dt.datetime.utcnow()
    exp = now + dt.timedelta(days=args.days)

    header = {"alg":"ES256","kid":args.key_id,"typ":"JWT"}
    payload = {
        "iss":"UltimateDRM",
        "product":"UltimateDRM/agent",
        "org":args.org,
        "plan":args.plan,
        "seats":args.seats,
        "features":args.features,
        "iat":int(now.timestamp()),
        "exp":int(exp.timestamp()),
        "jti": b64url(os.urandom(12)),
    }

    signing_input = (b64url_json(header) + "." + b64url_json(payload)).encode("ascii")

    key = load_key(args.priv)
    h = hashlib.sha256(signing_input).digest()
    sig = key.sign(h, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    token = signing_input.decode("ascii") + "." + b64url(sig)

    print(token)

if __name__ == "__main__":
    main()
