# frozen_string_literal: true
# Copyright (C) 2018 mwrap hackers <mwrap-public@80x24.org>
# License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
require 'test/unit'
require 'mwrap'
require 'rbconfig'
require 'tempfile'

class TestMwrap < Test::Unit::TestCase
  RB = "#{RbConfig::CONFIG['bindir']}/#{RbConfig::CONFIG['RUBY_INSTALL_NAME']}"

  mwrap_so = $".grep(%r{/mwrap\.so\z})[0]
  env = ENV.to_hash
  cur = env['LD_PRELOAD']
  env['LD_PRELOAD'] = cur ? "#{mwrap_so}:#{cur}".freeze : mwrap_so
  @@env = env.freeze
  inc = File.dirname(mwrap_so)
  @@cmd = %W(#{RB} -w --disable=gems -I#{inc} -rmwrap).freeze

  def test_mwrap_preload
    cmd = @@cmd + %w(
      -e ("helloworld"*1000).clear
      -e Mwrap.dump
    )
    Tempfile.create('junk') do |tmp|
      tmp.sync = true
      res = system(@@env, *cmd, err: tmp)
      assert res, $?.inspect
      tmp.rewind
      lines = tmp.readlines
      line_1 = lines.grep(/\s-e:1\b/)[0].strip
      assert_equal '10001', line_1.split(/\s+/)[0]
    end
  end

  def test_dump_via_destructor
    env = @@env.dup
    env['MWRAP'] = 'dump_fd:5'
    cmd = @@cmd + %w(-e ("0"*10000).clear)
    Tempfile.create('junk') do |tmp|
      tmp.sync = true
      res = system(env, *cmd, { 5 => tmp })
      assert res, $?.inspect
      tmp.rewind
      assert_match(/\b10001\s+-e:1$/, tmp.read)

      env['MWRAP'] = 'dump_fd:1,dump_min:10000'
      tmp.rewind
      tmp.truncate(0)
      res = system(env, *cmd, { 1 => tmp })
      assert res, $?.inspect
      tmp.rewind
      assert_match(/\b10001\s+-e:1$/, tmp.read)

      tmp.rewind
      tmp.truncate(0)
      env['MWRAP'] = "dump_path:#{tmp.path},dump_min:10000"
      res = system(env, *cmd)
      assert res, $?.inspect
      assert_match(/\b10001\s+-e:1$/, tmp.read)
    end
  end

  def test_clear
    cmd = @@cmd + %w(
      -e ("0"*10000).clear
      -e Mwrap.clear
      -e ("0"*20000).clear
      -e Mwrap.dump($stdout,9999)
    )
    Tempfile.create('junk') do |tmp|
      tmp.sync = true
      res = system(@@env, *cmd, { 1 => tmp })
      assert res, $?.inspect
      tmp.rewind
      buf = tmp.read
      assert_not_match(/\s+-e:1$/, buf)
      assert_match(/\b20001\s+-e:3$/, buf)
    end
  end

  # make sure we don't break commands spawned by an mwrap-ed Ruby process:
  def test_non_ruby_exec
    IO.pipe do |r, w|
      th = Thread.new { r.read }
      Tempfile.create('junk') do |tmp|
        tmp.sync = true
        env = @@env.merge('MWRAP' => "dump_path:#{tmp.path}")
        cmd = %w(perl -e print("HELLO_WORLD"))
        res = system(env, *cmd, out: w)
        w.close
        assert res, $?.inspect
        assert_match(/unknown/, tmp.read)
      end
      assert_equal "HELLO_WORLD", th.value
    end
  end
end
