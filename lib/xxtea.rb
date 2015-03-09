require 'xxtea/version'
require 'xxtea/xxtea'


module XXTEA
  def self.encrypt_hex(data, key)
    encrypt(data, key).unpack('H*').first
  end

  def self.decrypt_hex(data, key)
    decrypt([data].pack('H*'), key)
  end
end
