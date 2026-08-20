# frozen_string_literal: true

require_relative "test_helper"

class TestBigEndianInPlaceLongs2Bytes < Minitest::Test
  # Regression test for the big-endian in-place longs2bytes bug.
  #
  # decrypt reuses the same Ruby string buffer as both the uint32_t word
  # array and the byte output. On big-endian machines longs2bytes must swap
  # each word's bytes in place.

  def test_decrypt_words_with_distinct_bytes
    key = "0123456789abcdef"
    data = [
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xff,
    ].pack("C*")
    enc = XXTEA.encrypt(data, key)
    assert_equal data, XXTEA.decrypt(enc, key)
  end

  def test_decrypt_mixed_lengths
    key = "0123456789abcdef"
    256.times do |length|
      data = length.times.map { |i| (i * 7 + 13) & 0xff }.pack("C*")
      enc = XXTEA.encrypt(data, key)
      assert_equal data, XXTEA.decrypt(enc, key), "failed for length=#{length}"
    end
  end
end
