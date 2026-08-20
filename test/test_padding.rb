# frozen_string_literal: true

require_relative "test_helper"

class TestPadding8 < Minitest::Test
  VECTORS = JSON.parse(File.read(File.expand_path("vectors8.json", __dir__))).freeze

  def test_constants
    assert_equal :pkcs7_4_min8, XXTEA::PKCS7_4_MIN8
    assert_equal :pkcs7_8, XXTEA::PKCS7_8
  end

  def test_true_equals_pkcs7_4_min8
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    assert_equal XXTEA.encrypt(data, key, padding: true),
                 XXTEA.encrypt(data, key, padding: :pkcs7_4_min8)
    assert_equal XXTEA.encrypt(data, key, padding: true),
                 XXTEA.encrypt(data, key, padding: XXTEA::PKCS7_4_MIN8)
  end

  def test_false_equals_none
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    assert_equal XXTEA.encrypt(data, key, padding: false),
                 XXTEA.encrypt(data, key, padding: :none)
  end

  def test_string_name
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    assert_equal XXTEA.encrypt(data, key, padding: :pkcs7_8),
                 XXTEA.encrypt(data, key, padding: "pkcs7_8")
  end

  def test_xxteang_vectors
    VECTORS.each_with_index do |vec, i|
      data = [vec["data"]].pack("H*")
      key = [vec["key"]].pack("H*")
      expected = [vec["enc"]].pack("H*")

      enc = XXTEA.encrypt(data, key, padding: :pkcs7_8)
      assert_equal expected, enc, "encrypt mismatch at vector #{i} len=#{vec["len"]}"
      assert_equal vec["ct_len"], enc.bytesize

      dec = XXTEA.decrypt(enc, key, padding: :pkcs7_8)
      assert_equal data, dec, "decrypt mismatch at vector #{i} len=#{vec["len"]}"

      hexenc = XXTEA.encrypt_hex(data, key, padding: :pkcs7_8)
      assert_equal vec["enc"], hexenc
      assert_equal data, XXTEA.decrypt_hex(hexenc, key, padding: :pkcs7_8)
    end
  end

  def test_8_differs_from_4_for_8_byte_input
    key = "abcdefghijklmnop"
    data = "12345678"
    enc4 = XXTEA.encrypt(data, key, padding: :pkcs7_4_min8)
    enc8 = XXTEA.encrypt(data, key, padding: :pkcs7_8)
    refute_equal enc4, enc8
    assert_equal 12, enc4.bytesize
    assert_equal 16, enc8.bytesize
    assert_equal data.b, XXTEA.decrypt(enc4, key, padding: :pkcs7_4_min8)
    assert_equal data.b, XXTEA.decrypt(enc8, key, padding: :pkcs7_8)
  end

  def test_8_matches_4_for_short_inputs
    key = SecureRandom.random_bytes(16)
    8.times do |length|
      data = SecureRandom.random_bytes(length)
      enc4 = XXTEA.encrypt(data, key, padding: :pkcs7_4_min8)
      enc8 = XXTEA.encrypt(data, key, padding: :pkcs7_8)
      assert_equal enc4, enc8, "len=#{length} should match between :pkcs7_4_min8 and :pkcs7_8"
    end
  end

  def test_roundtrip_all_lengths
    key = SecureRandom.random_bytes(16)
    64.times do |length|
      data = SecureRandom.random_bytes(length)
      enc = XXTEA.encrypt(data, key, padding: :pkcs7_8)
      assert_equal 0, enc.bytesize % 8
      assert_operator enc.bytesize, :>=, 8
      assert_equal data, XXTEA.decrypt(enc, key, padding: :pkcs7_8), "length=#{length}"
    end
  end

  def test_8byte_edge
    key = SecureRandom.random_bytes(16)
    256.times do |last|
      data = ([0] * 7 + [last]).pack("C*")
      enc = XXTEA.encrypt(data, key, padding: :pkcs7_8)
      assert_equal 16, enc.bytesize
      assert_equal data, XXTEA.decrypt(enc, key, padding: :pkcs7_8)
    end
  end

  def test_empty_and_short
    key = SecureRandom.random_bytes(16)
    8.times do |length|
      data = SecureRandom.random_bytes(length)
      enc = XXTEA.encrypt(data, key, padding: :pkcs7_8)
      assert_equal 8, enc.bytesize
      assert_equal data, XXTEA.decrypt(enc, key, padding: :pkcs7_8)
    end
  end

  def test_cipher_object
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key, padding: :pkcs7_8)
    assert_equal XXTEA.encrypt(data, key, padding: :pkcs7_8), cipher.encrypt(data)
    assert_equal data, cipher.decrypt(cipher.encrypt(data))
    assert_match(/padding=pkcs7_8/, cipher.inspect)
  end

  def test_cipher_padding_constant
    key = SecureRandom.random_bytes(16)
    cipher = XXTEA.new(key, padding: XXTEA::PKCS7_8)
    assert_equal "12345678".b, cipher.decrypt(cipher.encrypt("12345678"))
  end

  def test_invalid_padding_value
    key = "k" * 16
    data = "12345678"
    assert_raises(TypeError) { XXTEA.encrypt(data, key, padding: 8) }
    assert_raises(TypeError) { XXTEA.encrypt(data, key, padding: 16) }
    assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :pkcs7) }
    assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :pkcs7_4) }
    assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :xxtea) }
    assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :pkcs7_16) }
    assert_raises(ArgumentError) { XXTEA.new(key, padding: :zero) }
  end

  def test_how_do_you_do_same_as_4byte
    data = "How do you do?"
    key = "Fine. And you?  "
    enc4 = XXTEA.encrypt(data, key)
    enc8 = XXTEA.encrypt(data, key, padding: :pkcs7_8)
    assert_equal enc4, enc8
    assert_equal "78f465eb1b4985887d11842ede853621", XXTEA.encrypt_hex(data, key, padding: :pkcs7_8)
  end

  def test_digits_xxteang_vector
    data = "0123456789"
    key = "abcdefghijklmnop"
    assert_equal "90f829f7271461d1d47efae4f5fde383",
                 XXTEA.encrypt_hex(data, key, padding: :pkcs7_8)
  end
end
