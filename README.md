# xxtea

[![CI](https://github.com/ifduyue/ruby-xxtea/actions/workflows/test.yml/badge.svg)](https://github.com/ifduyue/ruby-xxtea/actions/workflows/test.yml)
[![Gem Version](https://badge.fury.io/rb/xxtea.svg)](https://rubygems.org/gems/xxtea)

[XXTEA](https://en.wikipedia.org/wiki/XXTEA) implemented as a Ruby C extension, licensed under 2-clause BSD.

Ciphertext is compatible with the [Python xxtea](https://github.com/ifduyue/xxtea) package.

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

> **Note:** This implementation uses a **non-standard** 4-byte block PKCS#7
> padding instead of the conventional 8-byte or 16-byte block. For inputs
> shorter than 4 bytes, a non-standard hack pads an extra 4 bytes (producing
> pad values 5–8) to satisfy XXTEA's 2-word minimum. This means the output is
> **NOT** compatible with other XXTEA implementations. Pass `padding: false`
> for raw XXTEA (requires data length ≥ 8 and multiple of 4).

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
c = XXTEA.new(key)                       # rounds=0, padding=true
c = XXTEA.new(key, rounds: 64)           # override rounds
c = XXTEA.new(key, padding: false)       # disable padding
c = XXTEA.new(key, padding: false, rounds: 42)
```

`encrypt_hex` and `decrypt_hex` operate on ciphertext in a hexadecimal
representation. They are exactly equivalent to:

```ruby
hexenc = XXTEA.encrypt(s, key).unpack1("H*")
s == XXTEA.decrypt([hexenc].pack("H*"), key)  # => true
```

## Padding

Padding is enabled by default, using a **non-standard 4-byte block PKCS#7**
scheme. The pad byte value is `4 - (data.bytesize & 3)` (range 1–4), plus an
extra 4 bytes when the input is shorter than 4 bytes to meet XXTEA's 2-word
minimum (producing pad values 5–8).

Because padding always adds at least one byte, encrypting an 8-byte input
produces a 12-byte ciphertext. This is incompatible with other XXTEA
implementations that use a standard block size or skip padding altogether.
Use `padding: false` for raw, unpadded XXTEA.

```ruby
XXTEA.decrypt_hex(XXTEA.encrypt_hex("", key), key)   # => ""
XXTEA.decrypt_hex(XXTEA.encrypt_hex(" ", key), key)  # => " "
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

- Compatible with [Python xxtea](https://github.com/ifduyue/xxtea) (same padding, endianness, and rounds).
- The `XXTEA.encrypt(data, key)` / `XXTEA.decrypt(data, key)` class methods remain compatible with gem 0.0.1 for valid ciphertext. `XXTEA` is now a class rather than a module, and invalid padding raises `ArgumentError` instead of returning stripped bytes.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
