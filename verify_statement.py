#!/usr/bin/env python3
"""Verify an xChk SCITT signed statement with no network. Standard library only; uses verify_receipt.py beside it.

Usage:  python3 verify_statement.py xchk-scitt-<hash>.cose [--bundle xchk-receipt-<hash>.json] [--keys xchk-keys.json] [--json]
        python3 verify_statement.py xchk-install.cose --file xchk-install.sh --keys xchk-keys.json [--json]

The statement (4 Nov 2026) is a COSE_Sign1 (RFC 9052) that the xChk registry signs over ONE approved action record's
hash, for anyone to register in the SCITT transparency service they trust. Format: SCITT.md beside this file.

MIT License. Copyright (c) 2026 Sean MacGuire. Permission is hereby granted, free of charge, to any person
obtaining a copy of this file, to deal in it without restriction, subject to this notice being included.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

What is checked:
  1. the bytes are a tagged COSE_Sign1 (tag 18) in definite-length CBOR, and nothing follows it;
  2. the protected header: alg EdDSA (-8), a kid, payload_hash_alg SHA-256 (-16), CWT claims with iss, iat, and
     sub = urn:xchk:record:<payload hex>;
  3. the payload is 32 bytes (the record hash);
  4. the Ed25519 signature over Sig_structure ["Signature1", protected, h'', payload] verifies with the key whose
     keyId equals the kid, taken from --keys (the registry's /.well-known/xchk-keys.json, saved once) or from the
     bundle's pinned keys; a revoked key fails; no key at all fails (closed, never open);
  5. with --bundle: the payload equals the bundle's recordHash AND sha256(canonical(bundle.record)), so the
     statement names exactly that record. Run verify_receipt.py on the bundle for the record's own proof (seal,
     Merkle path, anchors, the person's signed answer); this file proves only the statement.

With --file (28 Nov 2026) the statement is one the registry signs over a FILE it serves, today its install script, so
that what is run is what was read and a script swapped on the web server without the registry's key fails:
  2'. sub = urn:xchk:install:<payload hex> (a record's statement is refused here, and a file's is refused without --file);
  5'. the payload equals sha256 of the file's bytes, exactly as they are on disk.
It says whose the file is and that these are the bytes. It does not say the file is safe: read it.

Exit 0 when every check passes, 1 when any fails, 2 on a usage error. Unprotected headers are reported, not judged: a
transparency service adds its receipt there after registration.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_receipt import b64d, canonical, ed25519_verify, key_id_for, load_key_document  # noqa: E402

COSE_SIGN1 = 18
ALG, KID, CWT_CLAIMS, PAYLOAD_HASH_ALG, PREIMAGE_TYPE, PAYLOAD_LOCATION = 1, 4, 15, 258, 259, 260
EDDSA, SHA256 = -8, -16
ISS, SUB, IAT = 1, 2, 6


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def cbor_decode(buf: bytes):
    """Definite-length CBOR: integers, byte and text strings, arrays, maps, tags. Anything else is an error."""
    pos = 0

    def arg(ai):
        nonlocal pos
        if ai < 24:
            return ai
        n = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
        if n is None:
            raise ValueError(f"unsupported CBOR additional info {ai} (indefinite lengths and floats are not allowed)")
        if pos + n > len(buf):
            raise ValueError("CBOR truncated")
        v = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
        return v

    def item(depth=0):
        nonlocal pos
        if depth > 16:
            raise ValueError("CBOR nested too deep")
        if pos >= len(buf):
            raise ValueError("CBOR truncated")
        b = buf[pos]
        pos += 1
        major, n = b >> 5, arg(b & 31)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major in (2, 3):
            if pos + n > len(buf):
                raise ValueError("CBOR truncated")
            v = buf[pos:pos + n]
            pos += n
            return bytes(v) if major == 2 else v.decode("utf-8")
        if major == 4:
            return [item(depth + 1) for _ in range(n)]
        if major == 5:
            m = {}
            for _ in range(n):
                k = item(depth + 1)
                if isinstance(k, (list, dict)):
                    raise ValueError("CBOR map key is not a scalar")
                if k in m:
                    raise ValueError(f"CBOR map has key {k!r} twice")
                m[k] = item(depth + 1)
            return m
        if major == 6:
            return Tag(n, item(depth + 1))
        raise ValueError(f"unsupported CBOR major type {major}")

    out = item()
    if pos != len(buf):
        raise ValueError(f"{len(buf) - pos} trailing bytes after the CBOR item")
    return out


def _bstr(b: bytes) -> bytes:
    n = len(b)
    if n < 24:
        h = bytes([0x40 | n])
    elif n < 0x100:
        h = bytes([0x58, n])
    elif n < 0x10000:
        h = bytes([0x59]) + n.to_bytes(2, "big")
    else:
        h = bytes([0x5A]) + n.to_bytes(4, "big")
    return h + b


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 §4.4: ["Signature1", body_protected, external_aad = h'', payload]."""
    return b"\x84\x6aSignature1" + _bstr(protected) + b"\x40" + _bstr(payload)


def candidate_keys(kid: str, keys_doc, bundle):
    """[(source, status, publicKeyRaw bytes)] for an Ed25519 key whose keyId is kid."""
    found = []
    if keys_doc:
        for status in ("keys", "retired", "revoked"):
            for k in keys_doc.get(status, []):
                if k.get("alg") == "ed25519" and k.get("keyId") == kid and k.get("publicKeyRaw"):
                    found.append(("--keys", status, b64d(k["publicKeyRaw"])))
    if bundle:
        rs = bundle.get("registrySignature") or {}
        for k in (rs.get("keys") or []) + (rs.get("retired") or []):
            if k.get("alg") == "ed25519" and k.get("publicKeyRaw"):
                raw = b64d(k["publicKeyRaw"])
                if key_id_for("ed25519", raw) == kid:
                    found.append(("bundle", "keys", raw))
    return found


def revoked_by_id(kid: str, keys_doc) -> list:
    """Every entry of the key document that revokes the Ed25519 key with this keyId, however the document says it (in
    `revoked`, or carrying revokedAt, or a status that is neither active nor retired), with or without its public key.
    9 Nov 2026 (private review of agentrust-io/integrations#350): candidate_keys drops an entry published without its
    raw key, so a revocation listed beside a still-active entry was invisible and the active key signed."""
    if not keys_doc:
        return []
    out = []
    for status in ("keys", "retired", "revoked"):
        for k in keys_doc.get(status, []):
            if k.get("alg") == "ed25519" and k.get("keyId") == kid and (
                    status == "revoked" or k.get("revokedAt") or k.get("status") not in (None, "active", "retired")):
                out.append(k)
    return out


def verify(path: str, bundle_path=None, keys_path=None, file_path=None) -> dict:
    checks = []

    def check(ok, what):
        checks.append({"ok": bool(ok), "check": what})
        return bool(ok)

    report = {"statement": path, "checks": checks, "ok": False}
    try:
        with open(path, "rb") as f:
            raw = f.read()
        top = cbor_decode(raw)
    except (OSError, ValueError, UnicodeDecodeError) as e:
        check(False, f"statement parses as CBOR: {e}")
        return report
    if not check(isinstance(top, Tag) and top.tag == COSE_SIGN1, "tagged COSE_Sign1 (tag 18)"):
        return report
    v = top.value
    if not check(isinstance(v, list) and len(v) == 4 and isinstance(v[0], bytes) and isinstance(v[1], dict)
                 and isinstance(v[2], bytes) and isinstance(v[3], bytes), "COSE_Sign1 is [protected bstr, unprotected map, payload bstr, signature bstr]"):
        return report
    prot_bytes, unprot, payload, sig = v
    try:
        prot = cbor_decode(prot_bytes)
    except (ValueError, UnicodeDecodeError) as e:
        check(False, f"protected header parses: {e}")
        return report
    if not check(isinstance(prot, dict), "protected header is a map"):
        return report
    check(prot.get(ALG) == EDDSA, "alg is EdDSA (-8)")
    kid_b = prot.get(KID)
    kid = kid_b.decode("utf-8", "replace") if isinstance(kid_b, bytes) else None
    check(bool(kid), "kid is present (the registry keyId)")
    check(prot.get(PAYLOAD_HASH_ALG) == SHA256, "payload_hash_alg is SHA-256 (-16)")
    check(len(payload) == 32, "payload is 32 bytes (a SHA-256 record hash)")
    rh = payload.hex()
    cwt = prot.get(CWT_CLAIMS)
    cwt_ok = check(isinstance(cwt, dict), "CWT claims (15) are in the protected header")
    if cwt_ok:
        check(isinstance(cwt.get(ISS), str) and cwt.get(ISS).startswith("https://"), "iss is the registry's https base")
        if file_path is None:
            check(cwt.get(SUB) == f"urn:xchk:record:{rh}", "sub names the same record as the payload")
        else:
            check(cwt.get(SUB) == f"urn:xchk:install:{rh}", "sub names a served file with the same hash as the payload (urn:xchk:install:)")
        check(isinstance(cwt.get(IAT), int) and cwt.get(IAT) > 0, "iat is a positive integer")
    report.update(recordHash=rh, kid=kid, iss=cwt.get(ISS) if cwt_ok else None,
                  payloadLocation=prot.get(PAYLOAD_LOCATION), preimageContentType=prot.get(PREIMAGE_TYPE),
                  unprotectedLabels=sorted(str(k) for k in unprot))

    keys_doc = bundle = None
    try:
        if keys_path:
            keys_doc = load_key_document(keys_path)
        if bundle_path:
            with open(bundle_path, "r", encoding="utf-8-sig") as f:
                bundle = json.load(f)
    except (OSError, ValueError) as e:
        check(False, f"inputs load: {e}")
        return report

    cands = candidate_keys(kid, keys_doc, bundle) if kid else []
    if not check(cands, "a key with this keyId is available (from --keys or the bundle)"):
        pass
    else:
        rv = revoked_by_id(kid, keys_doc)
        check(not any(s == "revoked" for _, s, _ in cands) and not rv, "the key is not revoked"
              + (f" (the key document revokes {kid}" + (" and ALSO lists it as active: it contradicts itself)" if any(s != "revoked" for src, s, _ in cands if src == "--keys") else ")") if rv else ""))
        tbs = sig_structure(prot_bytes, payload)
        good = [src for src, s, pub in cands if s != "revoked" and not rv and ed25519_verify(pub, tbs, sig)]
        check(good, "Ed25519 signature over the Sig_structure verifies" + (f" (key from {good[0]})" if good else ""))

    if file_path is not None:
        try:
            with open(file_path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
        except OSError as e:
            digest = None
            check(False, f"the file reads: {e}")
        if digest is not None:
            check(digest == rh, "payload equals sha256 of the file's bytes")
        check(bundle is None, "a file's statement is checked against the file, not a receipt bundle")
        report["file"] = file_path

    if bundle is not None:
        check(bundle.get("recordHash") == rh, "payload equals the bundle's recordHash")
        rec = bundle.get("record")
        check(isinstance(rec, dict) and hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest() == rh,
              "payload equals sha256(canonical(bundle.record))")
        check(isinstance(rec, dict) and rec.get("disposition") == "approved", "the record is an approved act")

    report["ok"] = bool(checks) and all(c["ok"] for c in checks)
    return report


def main(argv) -> int:
    args, opts = [], {}
    it = iter(argv)
    for a in it:
        if a in ("--bundle", "--keys", "--file"):
            opts[a] = next(it, None)
            if opts[a] is None:
                print(f"{a} needs a file", file=sys.stderr)
                return 2
        elif a == "--json":
            opts[a] = True
        elif a.startswith("--"):
            print(f"unknown option {a}", file=sys.stderr)
            return 2
        else:
            args.append(a)
    if len(args) != 1:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    r = verify(args[0], opts.get("--bundle"), opts.get("--keys"), opts.get("--file"))
    if opts.get("--json"):
        print(json.dumps(r, indent=2))
    else:
        for c in r["checks"]:
            print(("  ok   " if c["ok"] else "  FAIL ") + c["check"])
        what = f"file {r['file']} with sha256" if r.get("file") else "record"
        print(("VERIFIED: " if r["ok"] else "NOT VERIFIED: ") + f"statement over {what} {r.get('recordHash', '?')}")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
