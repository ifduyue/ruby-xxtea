# Changelog

## 1.0.0

- Rewrite as a Ruby C extension compatible with Python [xxtea](https://github.com/ifduyue/xxtea) 5.3.3.
- Keep `XXTEA.encrypt` / `XXTEA.decrypt` (16-byte key, non-standard 4-byte PKCS#7 padding).
- Add `padding:` and `rounds:` keyword arguments.
- Add `encrypt_hex` / `decrypt_hex`.
- Add `XXTEA.new(key, padding: true, rounds: 0)` cipher objects.
- Validate PKCS#7 padding on decrypt; reject invalid padding with `ArgumentError`.
- Encode ciphertext as little-endian bytes on all architectures.
- Require Ruby >= 3.1.

## 0.0.1 — 2015-03-08

- Initial release.
