# xxtea

[![CI](https://github.com/ifduyue/ruby-xxtea/actions/workflows/test.yml/badge.svg)](https://github.com/ifduyue/ruby-xxtea/actions/workflows/test.yml)
[![Gem Version](https://badge.fury.io/rb/xxtea.svg)](https://rubygems.org/gems/xxtea)

[XXTEA](https://en.wikipedia.org/wiki/XXTEA) implemented as a Ruby C extension, licensed under 2-clause BSD.

Default ciphertext is compatible with the [Python xxtea](https://github.com/ifduyue/xxtea) package.
`padding: :pkcs7_8` is compatible with [Python xxteang](https://github.com/ifduyue/xxteang).

The XXTEA algorithm takes a 128-bit key and operates on an array of 32-bit
integers (at least 2 integers), but it doesn't define the conversions between
bytes and array. Due to this reason, many XXTEA implementations out there are
not compatible with each other.

In this implementation, the conversions between bytes and array are taken care
of by `longs2bytes` and `bytes2longs`. A non-standard 4-byte block
[PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) padding is
used to make sure that the input bytes are padded to a multiple of 4-byte (the
size of a 32-bit integer) and at least 8-byte long (the size of two 32-bit
integers, which is required by the XXTEA algorithm). As a result of these
measures, you can encrypt not only texts, but also any binary bytes of any
length.

> **Note:** The default (`:pkcs7_4_min8`) is **not** standard 4-byte PKCS#7.
> For inputs shorter than 4 bytes it pads an extra 4 bytes (pad values 5–8)
> to satisfy XXTEA's 2-word minimum. Pass `padding: :pkcs7_8` for standard
> 8-byte PKCS#7 (compatible with Python xxteang), or `padding: false` for
> raw XXTEA (requires data length ≥ 8 and multiple of 4).

## Installation

A C compiler is required. Then:

```
$ gem install xxtea
```

Or add to your Gemfile:

```ruby
gem "xxtea"
```

## Usage

This gem provides four class methods: `encrypt`, `decrypt`, `encrypt_hex`, and
`decrypt_hex`, plus an `XXTEA` type for reusable cipher objects.

```ruby
require "xxtea"
require "securerandom"

key = SecureRandom.random_bytes(16)  # Key must be a 16-byte string.
s = "xxtea is good"

enc = XXTEA.encrypt(s, key)
dec = XXTEA.decrypt(enc, key)
s == dec  # => true

hexenc = XXTEA.encrypt_hex(s, key)
s == XXTEA.decrypt_hex(hexenc, key)  # => true

enc.unpack1("H*") == hexenc  # => true
```

## XXTEA Type

The `XXTEA` type holds a 16-byte key, rounds, and padding setting, so you can
encrypt and decrypt multiple times without passing them each call.

```ruby
cipher = XXTEA.new(key, padding: false, rounds: 128)
cipher
# => #<XXTEA:0x... padding=false rounds=128>

enc = cipher.encrypt("12345678")
cipher.decrypt(enc)  # => "12345678"

hexenc = cipher.encrypt_hex("12345678")
cipher.decrypt_hex(hexenc)  # => "12345678"
```

`rounds` defaults to `0` (auto), `padding` defaults to `true`.
`rounds: 0` means `6 + 52 / n`, where n is the number of 32-bit words in the data.
They are stored on the object and used by every `encrypt`, `decrypt`,
`encrypt_hex`, and `decrypt_hex` call:

```ruby
c = XXTEA.new(key)                         # rounds=0, padding=:pkcs7_4_min8
c = XXTEA.new(key, rounds: 64)             # override rounds
c = XXTEA.new(key, padding: false)         # disable padding
c = XXTEA.new(key, padding: :pkcs7_8)      # 8-byte PKCS#7
c = XXTEA.new(key, padding: :length_word_suffix)  # length word + zero padding
c = XXTEA.new(key, padding: false, rounds: 42)
```

`encrypt_hex` and `decrypt_hex` operate on ciphertext in a hexadecimal
representation. They are exactly equivalent to:

```ruby
hexenc = XXTEA.encrypt(s, key).unpack1("H*")
s == XXTEA.decrypt([hexenc].pack("H*"), key)  # => true
```

## Padding

`padding` accepts a scheme name, so more paddings can be added later:

| Value | Meaning |
| --- | --- |
| `true` or `:pkcs7_4_min8` (default) | 4-byte PKCS#7-like, padded to at least 8 bytes. Compatible with Python xxtea. Not standard 4-byte PKCS#7 |
| `:pkcs7_8` | Standard **8-byte** PKCS#7, compatible with Python xxteang |
| `:length_word_suffix` | Zero-pad to a 4-byte boundary, then append one little-endian `uint32` with the original length. Cocos Creator JSC files using this layout can be decrypted. Compatible with Python xxtea 6.2.0 |
| `:length_word_prefix` | Prepend one little-endian `uint32` with the original length, then zero-pad the data to a 4-byte boundary. Compatible with Python xxtea 6.2.0 |
| `false` or `:none` | No padding (raw XXTEA) |

`XXTEA::PKCS7_4_MIN8`, `XXTEA::PKCS7_8`, `XXTEA::LENGTH_WORD_PREFIX`, and
`XXTEA::LENGTH_WORD_SUFFIX` are aliases for the symbols.

The default `:pkcs7_4_min8` scheme uses pad byte value `4 - (data.bytesize & 3)`
(range 1–4), plus an extra 4 bytes when the input is shorter than 4 bytes
to meet XXTEA's 2-word minimum (producing pad values 5–8). Standard 4-byte
PKCS#7 never uses pad values 5–8. Because padding always adds at least one
byte, encrypting an 8-byte input produces a 12-byte ciphertext.

8-byte PKCS#7 uses pad byte value `8 - (data.bytesize & 7)` (range 1–8).
Encrypting an 8-byte input produces a 16-byte ciphertext.

The length-word schemes store the original byte length in a little-endian
`uint32` word, so the plaintext length must fit in 32 bits (`RangeError`
otherwise). The data is zero-padded to a 4-byte boundary around that word:
the length word is the last word for `:length_word_suffix` and the first
word for `:length_word_prefix`. Because of XXTEA's 2-word minimum, empty
input produces an 8-byte ciphertext in either scheme.

```ruby
XXTEA.decrypt_hex(XXTEA.encrypt_hex("", key), key)   # => ""
XXTEA.decrypt_hex(XXTEA.encrypt_hex(" ", key), key)  # => " "

XXTEA.encrypt("12345678", key).bytesize                                 # => 12  (:pkcs7_4_min8)
XXTEA.encrypt("12345678", key, padding: :pkcs7_8).bytesize              # => 16  (:pkcs7_8)
XXTEA.encrypt("12345678", key, padding: :length_word_suffix).bytesize   # => 12
XXTEA.encrypt("12345678", key, padding: :length_word_prefix).bytesize   # => 12
```

You can disable padding by setting `padding: false`.
In this case data will not be padded, so data length must be a multiple of 4
bytes and must not be less than 8 bytes. Otherwise `ArgumentError` will be
raised:

```ruby
XXTEA.encrypt_hex("", key, padding: false)
# ArgumentError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes

XXTEA.encrypt_hex("xxtea is good", key, padding: false)
# ArgumentError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes

XXTEA.decrypt_hex(XXTEA.encrypt_hex("12345678", key, padding: false), key, padding: false)
# => "12345678"
```

## Rounds

By default xxtea manipulates the input data for `6 + 52 / n` rounds,
where n denotes how many 32-bit integers the input data can fit in.
We can change this by setting the `rounds` parameter.

Do note that the more rounds it is, the more time will be consumed.
`rounds` must fit in a 32-bit unsigned integer; values exceeding
`2**32 - 1` raise `RangeError`.

```ruby
data = "0123456789"
key = "abcdefghijklmnop"
XXTEA.encrypt_hex(data, key)
# => "5b80b08a5d1923e4cd992dd5"
6 + 52 / ((data.bytesize + 3) / 4)  # 23
XXTEA.encrypt_hex(data, key, rounds: 23)
# => "5b80b08a5d1923e4cd992dd5"
XXTEA.encrypt_hex(data, key, rounds: 1024)
# => "1577bbf28c43ced93bd50720"
```

## Catching Exceptions

When calling these methods, an `ArgumentError`, `TypeError`, or `RangeError`
may be raised.

```ruby
begin
  XXTEA.decrypt("", key: "")
rescue => e
  puts "#{e.class} : #{e.message}"
end
# ArgumentError : Need a 16-byte key.

XXTEA.decrypt("", " " * 16)
# ArgumentError : Data length must be a multiple of 4 bytes and must not be less than 8 bytes

XXTEA.decrypt(" " * 8, " " * 16)
# ArgumentError : Invalid data, illegal padding. Could be using a wrong key.

XXTEA.decrypt_hex(" " * 8, " " * 16)
# ArgumentError : Non-hexadecimal digit found

XXTEA.decrypt_hex("abc", " " * 16)
# ArgumentError : Odd-length string

XXTEA.decrypt_hex("abcd", " " * 16)
# ArgumentError : Data length must be a multiple of 4 bytes and must not be less than 8 bytes

XXTEA.encrypt("x", "k" * 16, rounds: 2**32)
# RangeError : rounds value too large

XXTEA.new("short")
# ArgumentError : Need a 16-byte key.

XXTEA.new("k" * 16, rounds: 2**32)
# RangeError : rounds value too large
```

## Compatibility

- Compatible with [Python xxtea](https://github.com/ifduyue/xxtea) 6.2.0: all five padding schemes (`:pkcs7_4_min8`, `:pkcs7_8`, `:length_word_prefix`, `:length_word_suffix`, `:none`), endianness, and rounds.
- `padding: :pkcs7_8` is compatible with [Python xxteang](https://github.com/ifduyue/xxteang).
- The `XXTEA.encrypt(data, key)` / `XXTEA.decrypt(data, key)` class methods remain compatible with gem 0.0.1 for valid ciphertext. `XXTEA` is now a class rather than a module, and invalid padding raises `ArgumentError` instead of returning stripped bytes.

## Releasing

Push a `v*` tag (for example `v1.0.0`). [`.github/workflows/build.yml`](.github/workflows/build.yml) builds the gem, publishes it to RubyGems.org via [Trusted Publishing](https://guides.rubygems.org/trusted-publishing/), and creates a GitHub Release.

The trusted publisher on RubyGems.org must match:

- Repository owner: `ifduyue`
- Repository name: `ruby-xxtea`
- Workflow filename: `build.yml`
- Environment: `release`

## License

BSD-2-Clause. See [LICENSE](LICENSE).

