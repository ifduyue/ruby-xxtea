require 'minitest/autorun'
require 'minitest/spec'
require 'securerandom'

require 'xxtea'

describe XXTEA do
  data = 'How do you do?'
  key = 'Fine. And you?  '
  enc = "x\xF4e\xEB\eI\x85\x88}\x11\x84.\xDE\x856!".force_encoding Encoding::ASCII_8BIT
  hexenc = '78f465eb1b4985887d11842ede853621'

  it 'encrypt' do
    assert_equal XXTEA.encrypt(data, key), enc
  end

  it 'encrypt_hex' do
    assert_equal XXTEA.encrypt_hex(data, key), hexenc
  end

  it 'decrypt' do
    assert_equal XXTEA.decrypt(enc, key), data
  end

  it 'decrypt_hex' do
    assert_equal XXTEA.decrypt_hex(hexenc, key), data
  end

  it 'encrypt and decrypt' do
    2048.times do |i|
      key = SecureRandom.random_bytes 16
      data = SecureRandom.random_bytes i

      enc = XXTEA.encrypt data, key
      hexenc = XXTEA.encrypt_hex data, key

      assert_equal data, XXTEA.decrypt(enc, key)
      assert_equal data, XXTEA.decrypt_hex(hexenc, key)
    end
  end
end
