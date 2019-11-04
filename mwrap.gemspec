git_manifest = `git ls-files 2>/dev/null`.split("\n")
manifest = File.exist?('MANIFEST') ?
  File.readlines('MANIFEST').map!(&:chomp).delete_if(&:empty?) : git_manifest
if git_manifest[0] && manifest != git_manifest
  tmp = "MANIFEST.#$$.tmp"
  File.open(tmp, 'w') { |fp| fp.puts(git_manifest.join("\n")) }
  File.rename(tmp, 'MANIFEST')
  system('git add MANIFEST')
end

desc = `git describe --abbrev=4 HEAD`.strip.tr('-', '.').sub('v', '')

Gem::Specification.new do |s|
  s.name = 'mwrap'
  s.version = desc.empty? ? '2.1.0' : desc
  s.homepage = 'https://80x24.org/mwrap/'
  s.authors = ["Ruby hackers"]
  s.summary = 'LD_PRELOAD malloc wrapper for Ruby'
  s.executables = %w(mwrap)
  s.files = manifest
  s.description = <<~EOF
mwrap wraps all malloc, calloc, and realloc calls to trace the Ruby
source location of such calls and bytes allocated at each callsite.
  EOF
  s.email = %q{e@80x24.org}
  s.test_files = Dir['test/test_*.rb']
  s.extensions = %w(ext/mwrap/extconf.rb)

  s.add_development_dependency('test-unit', '~> 3.0')
  s.add_development_dependency('rake-compiler', '~> 1.0')
  s.licenses = %w(GPL-2.0+)
end
