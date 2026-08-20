# frozen_string_literal: true

require_relative "test_helper"

class TestXXTEA < Minitest::Test
  DATA = "How do you do?"
  KEY = "Fine. And you?  "
  ENC = "x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!".b
  HEXENC = "78f465eb1b4985887d11842ede853621"

  def test_version
    assert_kind_of Class, XXTEA
    assert_kind_of String, XXTEA::VERSION
    refute_empty XXTEA::VERSION
  end

  def test_encrypt
    assert_equal ENC, XXTEA.encrypt(DATA, KEY)
  end

  def test_encrypt_hex
    assert_equal HEXENC, XXTEA.encrypt_hex(DATA, KEY)
  end

  def test_decrypt
    assert_equal DATA.b, XXTEA.decrypt(ENC, KEY)
  end

  def test_decrypt_hex
    assert_equal DATA.b, XXTEA.decrypt_hex(HEXENC, KEY)
  end

  def test_readme_digits_vector
    data = "0123456789"
    key = "abcdefghijklmnop"
    assert_equal "5b80b08a5d1923e4cd992dd5", XXTEA.encrypt_hex(data, key)
    assert_equal 23, 6 + 52 / ((data.bytesize + 3) / 4)
    assert_equal "5b80b08a5d1923e4cd992dd5", XXTEA.encrypt_hex(data, key, rounds: 23)
    assert_equal "1577bbf28c43ced93bd50720", XXTEA.encrypt_hex(data, key, rounds: 1024)
  end

  def test_urandom
    2048.times do |i|
      key = SecureRandom.random_bytes(16)
      data = SecureRandom.random_bytes(i)
      enc = XXTEA.encrypt(data, key)
      assert_equal data, XXTEA.decrypt(enc, key)
    end
  end

  def test_zero_bytes
    2048.times do |i|
      data = "\0" * i

      key = SecureRandom.random_bytes(16)
      enc = XXTEA.encrypt(data, key)
      assert_equal data.b, XXTEA.decrypt(enc, key)

      key = "\0" * 16
      enc = XXTEA.encrypt(data, key)
      assert_equal data.b, XXTEA.decrypt(enc, key)
    end
  end

  def test_encrypt_nopadding
    key = SecureRandom.random_bytes(16)
    [8, 12, 16, 20].each do |i|
      data = SecureRandom.random_bytes(i)
      enc = XXTEA.encrypt(data, key, padding: false)
      assert_equal data, XXTEA.decrypt(enc, key, padding: false)
    end
  end

  def test_encrypt_hex_nopadding
    key = SecureRandom.random_bytes(16)
    [8, 12, 16, 20].each do |i|
      data = SecureRandom.random_bytes(i)
      enc = XXTEA.encrypt_hex(data, key, padding: false)
      assert_equal data, XXTEA.decrypt_hex(enc, key, padding: false)
    end
  end

  def test_encrypt_nopadding_zero
    key = SecureRandom.random_bytes(16)
    [8, 12, 16, 20].each do |i|
      data = "\0" * i
      enc = XXTEA.encrypt(data, key, padding: false)
      assert_equal data.b, XXTEA.decrypt(enc, key, padding: false)
    end
  end

  def test_encrypt_hex_nopadding_zero
    key = SecureRandom.random_bytes(16)
    [8, 12, 16, 20].each do |i|
      data = "\0" * i
      enc = XXTEA.encrypt_hex(data, key, padding: false)
      assert_equal data.b, XXTEA.decrypt_hex(enc, key, padding: false)
    end
  end

  def test_encrypt_decrypt_4byte_edge
    key = SecureRandom.random_bytes(16)
    256.times do |last|
      data = [0, 0, 0, last].pack("C*")
      enc = XXTEA.encrypt(data, key)
      assert_equal data, XXTEA.decrypt(enc, key), "4-byte edge failed at last=#{last}"
    end
  end

  def test_encrypt_decrypt_8byte_edge
    key = SecureRandom.random_bytes(16)
    256.times do |last|
      data = ([0] * 7 + [last]).pack("C*")
      enc = XXTEA.encrypt(data, key)
      assert_equal data, XXTEA.decrypt(enc, key), "8-byte edge failed at last=#{last}"
    end
  end

  def test_encrypt_decrypt_short_inputs
    key = SecureRandom.random_bytes(16)
    4.times do |length|
      data = SecureRandom.random_bytes(length)
      enc = XXTEA.encrypt(data, key)
      assert_equal data, XXTEA.decrypt(enc, key), "short input length=#{length} failed"
    end
  end

  def test_encrypt_decrypt_all_short_lengths
    key = SecureRandom.random_bytes(16)
    17.times do |length|
      8.times do
        data = SecureRandom.random_bytes(length)
        enc = XXTEA.encrypt(data, key)
        assert_equal data, XXTEA.decrypt(enc, key), "length=#{length} failed"
      end
    end
  end

  def test_hex_encode
    256.times do |i|
      key = SecureRandom.random_bytes(16)
      data = SecureRandom.random_bytes(i)
      enc = XXTEA.encrypt(data, key)
      hexenc = XXTEA.encrypt_hex(data, key)
      assert_equal enc.unpack1("H*"), hexenc
    end
  end

  def test_decrypt_empty_raises
    key = SecureRandom.random_bytes(16)
    assert_raises(ArgumentError) { XXTEA.decrypt("", key) }
    assert_raises(ArgumentError) { XXTEA.decrypt("", key, padding: true) }
    assert_raises(ArgumentError) { XXTEA.decrypt("", key, padding: false) }
  end

  def test_ciphertext_encoding
    enc = XXTEA.encrypt(DATA, KEY)
    assert_equal Encoding::ASCII_8BIT, enc.encoding
  end

  def test_hex_encoding
    hexenc = XXTEA.encrypt_hex(DATA, KEY)
    assert_equal Encoding::US_ASCII, hexenc.encoding
  end
end
