# frozen_string_literal: true

begin
  require "bundler/gem_tasks"
rescue LoadError
end
require "rake/extensiontask"
require "rake/testtask"

Rake::ExtensionTask.new("xxtea") do |ext|
  ext.lib_dir = "lib/xxtea"
end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/test_*.rb"]
  t.warning = true
end

task default: %i[compile test]
