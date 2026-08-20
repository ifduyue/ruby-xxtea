# frozen_string_literal: true

require_relative "test_helper"

class TestVectors < Minitest::Test
  VECTORS = JSON.parse(File.read(File.expand_path("vectors.json", __dir__))).freeze

  def test_python_compatible_vectors
    VECTORS.each_with_index do |vec, i|
      data = [vec["data"]].pack("H*")
      key = [vec["key"]].pack("H*")
      expected = [vec["enc"]].pack("H*")
      padding = vec["padding"]
      rounds = vec["rounds"]

      enc = XXTEA.encrypt(data, key, padding: padding, rounds: rounds)
      assert_equal expected, enc, "encrypt mismatch at vector #{i} note=#{vec["note"].inspect}"

      dec = XXTEA.decrypt(enc, key, padding: padding, rounds: rounds)
      assert_equal data, dec, "decrypt mismatch at vector #{i} note=#{vec["note"].inspect}"

      hexenc = XXTEA.encrypt_hex(data, key, padding: padding, rounds: rounds)
      assert_equal vec["enc"], hexenc, "encrypt_hex mismatch at vector #{i}"
      assert_equal data, XXTEA.decrypt_hex(hexenc, key, padding: padding, rounds: rounds)
    end
  end
end
