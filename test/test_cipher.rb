# frozen_string_literal: true

require_relative "test_helper"

class TestXXTEAType < Minitest::Test
  DATA = "How do you do?"
  KEY = "Fine. And you?  "
  ENC = "x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!".b

  def setup
    @cipher = XXTEA.new(KEY)
  end

  def test_encrypt
    assert_equal ENC, @cipher.encrypt(DATA)
  end

  def test_decrypt
    assert_equal DATA.b, @cipher.decrypt(ENC)
  end

  def test_roundtrip
    enc = @cipher.encrypt(DATA)
    assert_equal DATA.b, @cipher.decrypt(enc)
  end

  def test_urandom
    256.times do |i|
      key = SecureRandom.random_bytes(16)
      data = SecureRandom.random_bytes(i)
      cipher = XXTEA.new(key)
      enc = cipher.encrypt(data)
      assert_equal data, cipher.decrypt(enc)
    end
  end

  def test_zero_bytes
    256.times do |i|
      data = "\0" * i

      cipher = XXTEA.new(SecureRandom.random_bytes(16))
      enc = cipher.encrypt(data)
      assert_equal data.b, cipher.decrypt(enc)

      cipher2 = XXTEA.new("\0" * 16)
      enc = cipher2.encrypt(data)
      assert_equal data.b, cipher2.decrypt(enc)
    end
  end

  def test_encrypt_nopadding
    cipher = XXTEA.new(SecureRandom.random_bytes(16), padding: false)
    [8, 12, 16, 20].each do |i|
      data = SecureRandom.random_bytes(i)
      enc = cipher.encrypt(data)
      assert_equal data, cipher.decrypt(enc)
    end
  end

  def test_encrypt_nopadding_zero
    cipher = XXTEA.new(SecureRandom.random_bytes(16), padding: false)
    [8, 12, 16, 20].each do |i|
      data = "\0" * i
      enc = cipher.encrypt(data)
      assert_equal data.b, cipher.decrypt(enc)
    end
  end

  def test_rounds
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    [0, 1, 8, 32, 64, 128, 256].each do |r|
      cipher = XXTEA.new(key, rounds: r)
      enc = cipher.encrypt(data)
      assert_equal data, cipher.decrypt(enc)
    end
  end

  def test_different_rounds_produce_different_output
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    c0 = XXTEA.new(key, rounds: 0)
    c32 = XXTEA.new(key, rounds: 32)
    refute_equal c0.encrypt(data), c32.encrypt(data)
  end

  def test_matches_class_encrypt
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key)
    assert_equal XXTEA.encrypt(data, key), cipher.encrypt(data)
  end

  def test_matches_class_decrypt
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    enc = XXTEA.encrypt(data, key)
    cipher = XXTEA.new(key)
    assert_equal XXTEA.decrypt(enc, key), cipher.decrypt(enc)
  end

  def test_matches_class_with_rounds
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key, rounds: 42)
    enc_c = cipher.encrypt(data)
    enc_m = XXTEA.encrypt(data, key, rounds: 42)
    assert_equal enc_m, enc_c
    assert_equal XXTEA.decrypt(enc_c, key, rounds: 42), cipher.decrypt(enc_m)
  end

  def test_matches_class_nopadding
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key, padding: false)
    assert_equal XXTEA.encrypt(data, key, padding: false), cipher.encrypt(data)
  end

  def test_short_key
    assert_raises(ArgumentError) { XXTEA.new("short") }
    assert_raises(ArgumentError) { XXTEA.new("this key is way too long!!!") }
  end

  def test_rounds_overflow
    assert_raises(RangeError) { XXTEA.new(KEY, rounds: 2**32) }
  end

  def test_missing_required_arg
    assert_raises(ArgumentError) { XXTEA.new }
  end

  def test_invalid_rounds_type
    assert_raises(TypeError) { XXTEA.new(KEY, rounds: "not-an-int") }
  end

  def test_encrypt_hex
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key)
    hexenc = cipher.encrypt_hex(data)
    assert_equal data, cipher.decrypt_hex(hexenc)
  end

  def test_encrypt_hex_matches
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key)
    assert_equal XXTEA.encrypt_hex(data, key), cipher.encrypt_hex(data)
  end

  def test_decrypt_hex_matches
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    hexenc = XXTEA.encrypt_hex(data, key)
    cipher = XXTEA.new(key)
    assert_equal XXTEA.decrypt_hex(hexenc, key), cipher.decrypt_hex(hexenc)
  end

  def test_padding_construction
    key = SecureRandom.random_bytes(16)
    [true, false].each do |padding|
      cipher = XXTEA.new(key, padding: padding)
      assert_equal "12345678".b, cipher.decrypt(cipher.encrypt("12345678"))
    end
  end

  def test_inspect_hides_key
    inspected = @cipher.inspect
    refute_includes inspected, KEY
    assert_match(/padding=true/, inspected)
    assert_match(/rounds=0/, inspected)
  end

  def test_inspect_settings
    cipher = XXTEA.new(KEY, padding: false, rounds: 64)
    inspected = cipher.inspect
    assert_match(/padding=false/, inspected)
    assert_match(/rounds=64/, inspected)
  end

  def test_unknown_keyword
    assert_raises(ArgumentError) { XXTEA.new(KEY, bogus: 1) }
  end
end
