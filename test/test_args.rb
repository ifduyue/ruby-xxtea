# frozen_string_literal: true

require_relative "test_helper"

class TestArgPassing < Minitest::Test
  def setup
    @key = SecureRandom.random_bytes(16)
    @data = SecureRandom.random_bytes(32)
    @enc = XXTEA.encrypt(@data, @key)
    @hexenc = XXTEA.encrypt_hex(@data, @key)
  end

  def test_encrypt_keywords
    enc = XXTEA.encrypt(@data, @key, padding: true, rounds: 32)
    assert_equal @data, XXTEA.decrypt(enc, @key, rounds: 32)
  end

  def test_encrypt_rounds_only
    enc = XXTEA.encrypt(@data, @key, rounds: 32)
    assert_equal @data, XXTEA.decrypt(enc, @key, rounds: 32)
  end

  def test_encrypt_nopadding_keyword
    enc = XXTEA.encrypt(@data, @key, padding: false)
    assert_equal @data, XXTEA.decrypt(enc, @key, padding: false)
  end

  def test_decrypt_keywords
    assert_equal @data, XXTEA.decrypt(@enc, @key, padding: true)
    enc = XXTEA.encrypt(@data, @key, padding: true, rounds: 32)
    assert_equal @data, XXTEA.decrypt(enc, @key, padding: true, rounds: 32)
  end

  def test_encrypt_hex_keywords
    hexenc = XXTEA.encrypt_hex(@data, @key, padding: true, rounds: 32)
    assert_equal @data, XXTEA.decrypt_hex(hexenc, @key, rounds: 32)
  end

  def test_encrypt_hex_nopadding
    enc = XXTEA.encrypt_hex(@data, @key, padding: false)
    assert_equal @data, XXTEA.decrypt_hex(enc, @key, padding: false)
  end

  def test_decrypt_hex_keywords
    hexenc = XXTEA.encrypt_hex(@data, @key, padding: true, rounds: 32)
    assert_equal @data, XXTEA.decrypt_hex(hexenc, @key, padding: true, rounds: 32)
  end

  def test_missing_required_arg
    assert_raises(ArgumentError) { XXTEA.encrypt(@data) }
    assert_raises(ArgumentError) { XXTEA.decrypt(@enc) }
    assert_raises(ArgumentError) { XXTEA.encrypt_hex(@data) }
    assert_raises(ArgumentError) { XXTEA.decrypt_hex(@hexenc) }
  end

  def test_unknown_keyword
    assert_raises(ArgumentError) { XXTEA.encrypt(@data, @key, bogus: 1) }
    assert_raises(ArgumentError) { XXTEA.decrypt(@enc, @key, bogus: 1) }
    assert_raises(ArgumentError) { XXTEA.encrypt_hex(@data, @key, bogus: 1) }
    assert_raises(ArgumentError) { XXTEA.decrypt_hex(@hexenc, @key, bogus: 1) }
  end

  def test_invalid_rounds_type
    assert_raises(TypeError) { XXTEA.encrypt(@data, @key, rounds: "not-an-int") }
    assert_raises(TypeError) { XXTEA.decrypt(@enc, @key, rounds: 1.5) }
  end

  def test_too_many_positional_args
    assert_raises(ArgumentError) { XXTEA.encrypt(@data, @key, true) }
    assert_raises(ArgumentError) { XXTEA.decrypt(@enc, @key, true, 32) }
  end

  def test_rounds_overflow
    assert_raises(RangeError) { XXTEA.encrypt(@data, @key, rounds: 2**32) }
    assert_raises(RangeError) { XXTEA.decrypt(@enc, @key, rounds: 2**32) }
    assert_raises(RangeError) { XXTEA.encrypt_hex(@data, @key, rounds: 2**32) }
    assert_raises(RangeError) { XXTEA.decrypt_hex(@hexenc, @key, rounds: 2**32) }
    assert_raises(RangeError) { XXTEA.encrypt(@data, @key, rounds: -1) }
  end

  def test_short_key
    assert_raises(ArgumentError) { XXTEA.encrypt(@data, "short") }
    assert_raises(ArgumentError) { XXTEA.encrypt(@data, "this key is way too long!!!") }
    assert_raises(ArgumentError) { XXTEA.decrypt(@enc, "short") }
  end

  def test_nopadding_invalid_length
    key = "k" * 16
    err = assert_raises(ArgumentError) { XXTEA.encrypt("", key, padding: false) }
    assert_match(/multiple of 4/, err.message)
    err = assert_raises(ArgumentError) { XXTEA.encrypt("xxtea is good", key, padding: false) }
    assert_match(/multiple of 4/, err.message)
  end

  def test_invalid_padding
    key = " " * 16
    err = assert_raises(ArgumentError) { XXTEA.decrypt(" " * 8, key) }
    assert_match(/illegal padding/, err.message)
  end

  def test_hex_errors
    key = " " * 16
    err = assert_raises(ArgumentError) { XXTEA.decrypt_hex(" " * 8, key) }
    assert_match(/Non-hexadecimal/, err.message)
    err = assert_raises(ArgumentError) { XXTEA.decrypt_hex("abc", key) }
    assert_match(/Odd-length/, err.message)
    err = assert_raises(ArgumentError) { XXTEA.decrypt_hex("abcd", key) }
    assert_match(/multiple of 4/, err.message)
  end

  def test_uppercase_hex
    assert_equal @data, XXTEA.decrypt_hex(@hexenc.upcase, @key)
  end

  def test_to_str_accepted
    data = Object.new
    def data.to_str
      "How do you do?"
    end
    key = Object.new
    def key.to_str
      "Fine. And you?  "
    end
    enc = XXTEA.encrypt(data, key)
    assert_equal "x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!".b, enc
  end
end
