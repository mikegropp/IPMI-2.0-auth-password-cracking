
Captures one RAKP challenge, prints the exact message used for HMAC-SHA1, and can verify a known password offline.


## Quick Start

Capture a single challenge for a known username:

```powershell
python ipmi_rakp_hmac.py capture <BMC IP> --user admin
```

Capture a challenge and immediately test a known password against the returned HMAC:

```powershell
python ipmi_rakp_hmac.py capture <BMC IP> --user admin --password <password>
```

Recompute the digest later from a saved `message_hex` value:

```powershell
python ipmi_rakp_hmac.py verify --message-hex <message_hex> --password <password> --hmac <expected_hmac>
```

If the password is correct for that exact capture, `password_match=true`.

## What Is Actually Hashed

The RAKP HMAC is ordinary HMAC-SHA1, but the message is not a human-readable string. It is this exact binary blob:

```text
console_session_id
|| bmc_session_id (little-endian)
|| console_random_id
|| bmc_random_id
|| bmc_guid
|| 0x14
|| len(username)
|| username
```

In Python terms, the digest is:

```python
hmac.new(password.encode("utf-8"), message_bytes, hashlib.sha1).hexdigest()
```

The most common reason for a mismatch is rebuilding `message_bytes` incorrectly.

## Why Manual Recomputations Often Fail

- `bmc_session_id` must be packed little-endian. If the script prints `f136691f`, the hashed bytes are `1f6936f1`.
- `message_hex` must be decoded with `bytes.fromhex(...)`. Do not hash the printable hex string.
- The challenge changes every run because the session IDs and random values change every run.
- The username is part of the message. `admin` and `ADMIN` do not hash the same way.

If a password does not match, first verify that you are using the exact `message_hex` from the same capture as the `hmac_sha1` value.

## Example: Offline Verification

If you already have `message_hex`, you can check a candidate password without touching the target again:

```python
import hashlib
import hmac

message = bytes.fromhex("<message_hex>")
digest = hmac.new(b"<password>", message, hashlib.sha1).hexdigest()
print(digest)
```

The script wraps this in:

```powershell
python ipmi_rakp_hmac.py verify --message-hex <message_hex> --password <password> --hmac <expected_hmac>
```

## Hashcat Format

The script prints a Hashcat-ready line:

```text
<message_hex>:<hmac_sha1>
```

For IPMI 2.0 RAKP HMAC-SHA1, use Hashcat mode `7300`.

## Notes

- `capture` uses a single username and a single challenge capture.
- `verify` is fully offline and only needs `message_hex`.
- This repo intentionally focuses on inspection and verification rather than broad password testing.
