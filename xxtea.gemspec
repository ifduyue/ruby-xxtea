# -*- encoding: utf-8 -*-

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'xxtea/version'
Gem::Specification.new do |gem|
  gem.name = "xxtea"
  gem.version = XXTEA::VERSION
  gem.authors = ["Yue Du"]
  gem.email = ["ifduyue@gmail.com"]
  gem.description = %q{Ruby xxtea module}
  gem.summary = %q{Ruby xxtea module}
  gem.homepage = "http://github.com/ifduyue/xxtea"
  gem.license = 'BSD'
  gem.files = `git ls-files`.split($/)
  gem.executables = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.extensions = ["ext/xxtea/extconf.rb"]
end
