# frozen_string_literal: true

require_relative "lib/xxtea/version"

Gem::Specification.new do |spec|
  spec.name = "xxtea"
  spec.version = XXTEA::VERSION
  spec.authors = ["Yue Du"]
  spec.email = ["ifduyue@gmail.com"]

  spec.summary = "XXTEA block cipher as a Ruby C extension"
  spec.description = <<~DESC
    XXTEA implemented as a Ruby C extension. Ciphertext is compatible with the
    Python xxtea package: little-endian 32-bit words and non-standard 4-byte
    PKCS#7 padding.
  DESC
  spec.homepage = "https://github.com/ifduyue/ruby-xxtea"
  spec.license = "BSD-2-Clause"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/master/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    Dir[
      "lib/**/*.rb",
      "ext/**/*.{c,h,rb}",
      "LICENSE",
      "README.md",
      "CHANGELOG.md",
    ]
  end
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/xxtea/extconf.rb"]
end
