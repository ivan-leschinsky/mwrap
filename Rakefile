# Copyright (C) 2018 mwrap hackers <mwrap-public@80x24.org>
# License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
require 'rake/testtask'
begin
  require 'rake/extensiontask'
  Rake::ExtensionTask.new('mwrap')
rescue LoadError
  warn 'rake-compiler not available, cross compiling disabled'
end

Rake::TestTask.new(:test)
task :test => :compile
task :default => :compile

c_files = File.readlines('MANIFEST').grep(%r{ext/.*\.[ch]$}).map!(&:chomp!)
task 'compile:mwrap' => c_files
