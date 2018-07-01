git_manifest = `git ls-files 2>/dev/null`.split("\n")
manifest = File.exist?('MANIFEST') ?
  File.readlines('MANIFEST').map!(&:chomp).delete_if(&:empty?) : git_manifest
if git_manifest[0] && manifest != git_manifest
  tmp = "MANIFEST.#$$.tmp"
  File.open(tmp, 'w') { |fp| fp.puts(git_manifest.join("\n")) }
  File.rename(tmp, 'MANIFEST')
  system('git add MANIFEST')
end

Gem::Specification.new do |s|
  s.name = 'mwrap'
  s.version = '0.0.0'
  s.homepage = 'https://80x24.org/mwrap.git'
  s.authors = ["Ruby hackers"]
  s.summary = 'LD_PRELOAD malloc wrapper for Ruby'
  s.executables = %w(mwrap)
  s.files = manifest
  s.description = <<~EOF
  EOF

  s.email = %q{e@80x24.org}
  s.test_files = Dir['test/test_*.rb']
  s.extensions = %w(ext/mwrap/extconf.rb)

  s.add_development_dependency('test-unit', '~> 3.0')
  s.add_development_dependency('rake-compiler', '~> 1.0')
  s.licenses = %w(GPL-2.0+)
end
