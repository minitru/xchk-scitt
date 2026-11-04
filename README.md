# xChk SCITT signed statement

*4 November 2026. Format 1.*

An xChk registry offers a SCITT signed statement for any action record that a verified person approved. The
statement is a COSE_Sign1 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) over the record's hash. Anyone may
register it in the SCITT transparency service they trust. The registry signs; it does not register, so no log is a
dependency of the registry, and no record enters a log unless someone chose to put it there.

The statement is **hash only**. Its payload is the 32-byte record hash. The record itself, which names the approver,
stays in the receipt bundle that the statement points to. A log that holds the statement holds no name, email, photo,
command or plate.

## This repository

| | |
|---|---|
| `verify_statement.py` | the offline checker for a statement (standard library only) |
| `verify_receipt.py` | the offline checker for a receipt bundle; `verify_statement.py` uses its Ed25519 and canonical JSON |
| `examples/` | a real statement from https://in.xchk.io, its receipt bundle and the registry's key document |
| `tests/` | `python -m pytest tests` (needs `pytest`; `dilithium-py` for the hybrid receipt checks) |

Try it:

```bash
python3 verify_statement.py examples/xchk-scitt-aa2bfd5b1d9b.cose --bundle examples/xchk-receipt-aa2bfd5b1d9b.json --keys examples/in.xchk.io-xchk-keys.json
```

## Where to get one

| | |
|---|---|
| Receipt page | `https://<registry>/receipt.html?h=<record hash>` — the **SCITT statement** button, shown only for approved acts |
| Statement | `GET https://<registry>/api/receipt/<record hash>/statement.cose` (`application/cose; cose-type="cose-sign1"`; 409 for a record that is not an approved act) |
| Receipt bundle (the preimage and its proofs) | `GET https://<registry>/api/receipt/<record hash>/bundle` |
| Registry keys | `https://<registry>/.well-known/xchk-keys.json` |

## The bytes

`COSE_Sign1` with CBOR tag 18, deterministic encoding (RFC 8949 §4.2.1):

```
18([
  protected: bstr .cbor {
      1: -8,                                   ; alg: EdDSA (Ed25519)
      4: h'<keyId as UTF-8>',                  ; kid: the keyId of the key in xchk-keys.json (16 hex characters)
     15: {                                     ; CWT claims (RFC 9597)
          1: "https://<registry>",             ;   iss
          2: "urn:xchk:record:<record hash>",  ;   sub
          6: <record time, seconds>            ;   iat: the record's own ts, so the bytes are deterministic
        },
    258: -16,                                  ; payload_hash_alg: SHA-256 (COSE hash envelope)
    259: "application/vnd.xchk.action-record+json",   ; preimage_content_type: the canonical record JSON
    260: "https://<registry>/api/receipt/<record hash>/bundle"   ; payload_location
  },
  unprotected: {},                             ; a transparency service adds its receipt here on registration
  payload: h'<record hash, 32 bytes>',
  signature: h'<64-byte Ed25519 signature>'
])
```

The signature is over `Sig_structure = ["Signature1", protected, h'', payload]` (RFC 9052 §4.4). The same record
always yields the same bytes: `iat` is the record's time and Ed25519 is deterministic. Registering it twice registers
one statement.

The record hash is `sha256` over the UTF-8 bytes of the record's canonical JSON (keys sorted, no whitespace), as the
bundle's `canonicalization` field states. The statement is signed with Ed25519 only. Receipts and seals are also
signed with ML-DSA-65, but COSE has no registered hybrid of the two yet.

## Checking one, with no network

```bash
python3 verify_statement.py xchk-scitt-<hash>.cose --keys xchk-keys.json --bundle xchk-receipt-<hash>.json
```

Standard library only. It uses `verify_receipt.py`, which must sit beside it. It checks the structure, the protected
header, that `sub` and the payload name the same record, the Ed25519 signature with the key named by `kid`, and that
the key is not revoked. With `--bundle` it also checks that the payload equals the bundle's `recordHash` and
`sha256(canonical(record))`, and that the record is an approved act. Without a key it fails; it never passes open.
Exit 0 verified, 1 not verified, 2 usage.

`verify_statement.py` proves the statement only. For the record's own proof (its seal, the Merkle path, the anchors
and the person's signed answer), run `verify_receipt.py` on the bundle:

```bash
python3 verify_receipt.py xchk-receipt-<hash>.json --require-approval --keys xchk-keys.json
```

## Using it as evidence elsewhere

A system that refers to an xChk approval, for example an agent action record in another log, should refer to it by
the **record hash** (the statement's payload and `sub`), not by the hash of the bundle file. The record hash is fixed
when the record is sealed; a bundle is re-served and its bytes can differ between fetches.

## Where this lives

Public copy: <https://github.com/minitru/xchk-scitt>. Served copies: `https://in.xchk.io/verify/SCITT.md`,
`verify_statement.py`, `verify_receipt.py`.

## Licence

MIT, as in each file's header.
