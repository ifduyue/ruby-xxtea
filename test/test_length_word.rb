# frozen_string_literal: true

require_relative "test_helper"

class TestLengthWordPadding < Minitest::Test
  SUFFIX_VECTORS = JSON.parse(File.read(File.expand_path("vectors_length_word.json", __dir__))).freeze
  PREFIX_VECTORS = JSON.parse(File.read(File.expand_path("vectors_length_word_prefix.json", __dir__))).freeze

  def test_constants
    assert_equal :length_word_prefix, XXTEA::LENGTH_WORD_PREFIX
    assert_equal :length_word_suffix, XXTEA::LENGTH_WORD_SUFFIX
  end

  def test_string_name
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    assert_equal XXTEA.encrypt(data, key, padding: :length_word_prefix),
                 XXTEA.encrypt(data, key, padding: "length_word_prefix")
    assert_equal XXTEA.encrypt(data, key, padding: :length_word_suffix),
                 XXTEA.encrypt(data, key, padding: "length_word_suffix")
  end

  def test_suffix_vectors
    SUFFIX_VECTORS.each_with_index do |vec, i|
      run_vector(vec, i, padding: :length_word_suffix)
    end
  end

  def test_prefix_vectors
    PREFIX_VECTORS.each_with_index do |vec, i|
      run_vector(vec, i, padding: :length_word_prefix)
    end
  end

  def test_ciphertext_size
    key = SecureRandom.random_bytes(16)
    [:length_word_suffix, :length_word_prefix].each do |padding|
      64.times do |length|
        data = SecureRandom.random_bytes(length)
        enc = XXTEA.encrypt(data, key, padding: padding)
        # Data zero-padded to a 4-byte boundary + one length word,
        # with the XXTEA 2-word minimum for empty input.
        expected = [((length + 3) / 4 * 4) + 4, 8].max
        assert_equal expected, enc.bytesize, "padding=#{padding} len=#{length}"
      end
    end
  end

  def test_roundtrip_all_lengths
    key = SecureRandom.random_bytes(16)
    [:length_word_suffix, :length_word_prefix].each do |padding|
      128.times do |length|
        data = SecureRandom.random_bytes(length)
        enc = XXTEA.encrypt(data, key, padding: padding)
        assert_equal 0, enc.bytesize % 4
        assert_operator enc.bytesize, :>=, 8
        assert_equal data, XXTEA.decrypt(enc, key, padding: padding),
                     "padding=#{padding} length=#{length}"

        hexenc = XXTEA.encrypt_hex(data, key, padding: padding)
        assert_equal enc.unpack1("H*"), hexenc
        assert_equal data, XXTEA.decrypt_hex(hexenc, key, padding: padding)
      end
    end
  end

  def test_empty_and_short
    key = SecureRandom.random_bytes(16)
    [:length_word_suffix, :length_word_prefix].each do |padding|
      8.times do |length|
        data = SecureRandom.random_bytes(length)
        enc = XXTEA.encrypt(data, key, padding: padding)
        expected = [((length + 3) / 4 * 4) + 4, 8].max
        assert_equal expected, enc.bytesize, "padding=#{padding} len=#{length}"
        assert_equal data, XXTEA.decrypt(enc, key, padding: padding)
        assert_equal data, XXTEA.decrypt_hex(enc.unpack1("H*"), key, padding: padding)
      end
    end
    # Empty input is one zero word plus the zero length word before
    # encryption, so both modes produce identical 8-byte ciphertexts.
    enc_suffix = XXTEA.encrypt("", key, padding: :length_word_suffix)
    enc_prefix = XXTEA.encrypt("", key, padding: :length_word_prefix)
    assert_equal 8, enc_suffix.bytesize
    assert_equal enc_suffix, enc_prefix
  end

  def test_zero_data
    key = "\0" * 16
    [:length_word_suffix, :length_word_prefix].each do |padding|
      32.times do |length|
        data = "\0" * length
        enc = XXTEA.encrypt(data, key, padding: padding)
        assert_equal data.b, XXTEA.decrypt(enc, key, padding: padding)
      end
    end
  end

  def test_suffix_and_prefix_differ
    key = "abcdefghijklmnop"
    data = "0123456789"
    enc_suffix = XXTEA.encrypt(data, key, padding: :length_word_suffix)
    enc_prefix = XXTEA.encrypt(data, key, padding: :length_word_prefix)
    refute_equal enc_suffix, enc_prefix
    refute_equal XXTEA.encrypt(data, key, padding: :pkcs7_4_min8), enc_suffix
  end

  def test_leftover_bytes_must_be_zero
    key = SecureRandom.random_bytes(16)
    raw = [0xAA, 0x01, 0x01, 0x01, 1, 0, 0, 0].pack("C*")
    enc = XXTEA.encrypt(raw, key, padding: false)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc, key, padding: :length_word_suffix) }
    raw_ok = [0xAA, 0, 0, 0, 1, 0, 0, 0].pack("C*")
    enc_ok = XXTEA.encrypt(raw_ok, key, padding: false)
    assert_equal "\xAA".b, XXTEA.decrypt(enc_ok, key, padding: :length_word_suffix)

    raw = [1, 0, 0, 0, 0xAA, 0x01, 0x01, 0x01].pack("C*")
    enc = XXTEA.encrypt(raw, key, padding: false)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc, key, padding: :length_word_prefix) }
    raw_ok = [1, 0, 0, 0, 0xAA, 0, 0, 0].pack("C*")
    enc_ok = XXTEA.encrypt(raw_ok, key, padding: false)
    assert_equal "\xAA".b, XXTEA.decrypt(enc_ok, key, padding: :length_word_prefix)
  end

  def test_empty_extra_word_must_be_zero
    key = SecureRandom.random_bytes(16)
    raw = [1, 0, 0, 0, 0, 0, 0, 0].pack("C*")
    enc = XXTEA.encrypt(raw, key, padding: false)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc, key, padding: :length_word_suffix) }

    raw = [0, 0, 0, 0, 1, 0, 0, 0].pack("C*")
    enc = XXTEA.encrypt(raw, key, padding: false)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc, key, padding: :length_word_prefix) }

    raw_ok = "\0".b * 8
    enc_ok = XXTEA.encrypt(raw_ok, key, padding: false)
    assert_equal "".b, XXTEA.decrypt(enc_ok, key, padding: :length_word_suffix)
    assert_equal "".b, XXTEA.decrypt(enc_ok, key, padding: :length_word_prefix)
    assert_equal enc_ok, XXTEA.encrypt("", key, padding: :length_word_suffix)
    assert_equal enc_ok, XXTEA.encrypt("", key, padding: :length_word_prefix)
  end

  def test_length_word_is_little_endian
    key = SecureRandom.random_bytes(16)
    [0, 1, 2, 3, 4, 5, 127, 128, 255, 256, 257, 0x0102, 0x010203].each do |length|
      data = "\xAA".b * length
      enc = XXTEA.encrypt(data, key, padding: :length_word_suffix)
      raw = XXTEA.decrypt(enc, key, padding: false)
      le = raw[-4, 4].unpack1("V")
      be = raw[-4, 4].unpack1("N")
      assert_equal length, le, "suffix len=#{length}"
      refute_equal length, be, "suffix len=#{length}" if le != be

      enc = XXTEA.encrypt(data, key, padding: :length_word_prefix)
      raw = XXTEA.decrypt(enc, key, padding: false)
      le = raw[0, 4].unpack1("V")
      be = raw[0, 4].unpack1("N")
      assert_equal length, le, "prefix len=#{length}"
      refute_equal length, be, "prefix len=#{length}" if le != be
    end
  end

  def test_invalid_length_word
    key = SecureRandom.random_bytes(16)
    enc = XXTEA.encrypt("A" * 16, key, padding: :length_word_suffix)
    4.times do |i|
      bad = enc.dup
      bad.setbyte(-(i + 1), bad.getbyte(-(i + 1)) ^ 0xFF)
      assert_raises(ArgumentError) { XXTEA.decrypt(bad, key, padding: :length_word_suffix) }
    end

    enc = XXTEA.encrypt("A" * 16, key, padding: :length_word_prefix)
    4.times do |i|
      bad = enc.dup
      bad.setbyte(i, bad.getbyte(i) ^ 0xFF)
      assert_raises(ArgumentError) { XXTEA.decrypt(bad, key, padding: :length_word_prefix) }
    end

    # High-bit length word must reject without signed overflow on 32-bit.
    raw = [0xAA, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF].pack("C*")
    enc = XXTEA.encrypt(raw, key, padding: false)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc, key, padding: :length_word_suffix) }
    raw = [0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0, 0, 0].pack("C*")
    enc = XXTEA.encrypt(raw, key, padding: false)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc, key, padding: :length_word_prefix) }

    enc = XXTEA.encrypt("0123456789", key, padding: :length_word_suffix)
    assert_raises(ArgumentError) { XXTEA.decrypt(enc[0...12], key, padding: :length_word_suffix) }
  end

  def test_cipher_object
    key = SecureRandom.random_bytes(16)
    data = SecureRandom.random_bytes(32)
    cipher = XXTEA.new(key, padding: :length_word_prefix)
    assert_equal XXTEA.encrypt(data, key, padding: :length_word_prefix), cipher.encrypt(data)
    assert_equal data, cipher.decrypt(cipher.encrypt(data))
    assert_match(/padding=length_word_prefix/, cipher.inspect)

    cipher = XXTEA.new(key, padding: XXTEA::LENGTH_WORD_SUFFIX)
    assert_equal XXTEA.encrypt(data, key, padding: :length_word_suffix), cipher.encrypt(data)
    assert_match(/padding=length_word_suffix/, cipher.inspect)
  end

  def test_invalid_padding_value
    key = "k" * 16
    data = "12345678"
    assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :length_word) }
    assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :zero_pad) }
    err = assert_raises(ArgumentError) { XXTEA.encrypt(data, key, padding: :bogus) }
    assert_match(/:length_word_prefix/, err.message)
    assert_match(/:length_word_suffix/, err.message)
  end

  private

  def run_vector(vec, i, padding:)
    data = [vec["data"]].pack("H*")
    key = [vec["key"]].pack("H*")
    expected = [vec["enc"]].pack("H*")

    enc = XXTEA.encrypt(data, key, padding: padding)
    assert_equal expected, enc, "encrypt mismatch at vector #{i} len=#{vec["len"]}"
    assert_equal vec["ct_len"], enc.bytesize

    dec = XXTEA.decrypt(enc, key, padding: padding)
    assert_equal data, dec, "decrypt mismatch at vector #{i} len=#{vec["len"]}"

    hexenc = XXTEA.encrypt_hex(data, key, padding: padding)
    assert_equal vec["enc"], hexenc
    assert_equal data, XXTEA.decrypt_hex(hexenc, key, padding: padding)
  end
end
