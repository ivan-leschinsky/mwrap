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
      assert_match(/\b10001\s+1\s+-e:1$/, tmp.read)

      env['MWRAP'] = 'dump_fd:1,dump_min:10000'
      tmp.rewind
      tmp.truncate(0)
      res = system(env, *cmd, { 1 => tmp })
      assert res, $?.inspect
      tmp.rewind
      assert_match(/\b10001\s+1\s+-e:1$/, tmp.read)

      tmp.rewind
      tmp.truncate(0)
      env['MWRAP'] = "dump_path:#{tmp.path},dump_min:10000"
      res = system(env, *cmd)
      assert res, $?.inspect
      assert_match(/\b10001\s+1\s+-e:1$/, tmp.read)

      tmp.rewind
      tmp.truncate(0)
      env['MWRAP'] = "dump_path:#{tmp.path},dump_heap:5"
      res = system(env, *cmd)
      assert res, $?.inspect
      assert_match %r{lifespan_stddev}, tmp.read
    end
  end

  def test_cmake
    begin
      exp = `cmake -h`
    rescue Errno::ENOENT
      warn 'cmake missing'
      return
    end
    assert_not_predicate exp.strip, :empty?
    env = @@env.merge('MWRAP' => 'dump_fd:1')
    out = IO.popen(env, %w(cmake -h), &:read)
    assert out.start_with?(exp), 'original help exists'
    assert_not_equal exp, out, 'includes dump output'
    dump = out.delete_prefix(exp)
    assert_match(/\b0x[a-f0-9]+\b/s, dump, 'dump output has addresses')
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
      assert_match(/\b20001\s+1\s+-e:3$/, buf)
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
        assert_match(/0x[a-f0-9]+\b/, tmp.read)
      end
      assert_equal "HELLO_WORLD", th.value
    end
  end

  # some URCU flavors use USR1, ensure the one we choose does not
  def test_sigusr1_works
    cmd = @@cmd + %w(
      -e STDOUT.sync=true
      -e trap(:USR1){p("HELLO_WORLD")}
      -e END{Mwrap.dump}
      -e puts -e STDIN.read)
    IO.pipe do |r, w|
      IO.pipe do |r2, w2|
        pid = spawn(@@env, *cmd, in: r2, out: w, err: '/dev/null')
        r2.close
        w.close
        assert_equal "\n", r.gets
        buf = +''
        10.times { Process.kill(:USR1, pid) }
        while IO.select([r], nil, nil, 0.1)
          case tmp = r.read_nonblock(1000, exception: false)
          when String
            buf << tmp
          end
        end
        w2.close
        Process.wait(pid)
        assert_predicate $?, :success?, $?.inspect
        assert_equal(["\"HELLO_WORLD\"\n"], buf.split(/^/).uniq)
      end
    end
  end

  def test_reset
    assert_nil Mwrap.reset
  end

  def test_each
    cmd = @@cmd + %w(
      -e ("0"*10000).clear
      -e h={}
      -e Mwrap.each(1000){|a,b,c|h[a]=[b,c]}
      -e puts(Marshal.dump(h))
    )
    r = IO.popen(@@env, cmd, 'r')
    h = Marshal.load(r.read)
    assert_not_predicate h, :empty?
    h.each_key { |k| assert_kind_of String, k }
    h.each_value do |total,calls|
      assert_operator total, :>, 0
      assert_operator calls, :>, 0
      assert_operator total, :>=, calls
    end
  end

  def test_aref_each
    cmd = @@cmd + %w(
      -e count=GC.count
      -e GC.disable
      -e keep=("0"*10000)
      -e loc=Mwrap["-e:3"]
      -e loc.each{|size,gen|p([size,gen,count])}
    )
    buf = IO.popen(@@env, cmd, &:read)
    assert_predicate $?, :success?
    assert_match(/\A\[\s*\d+,\s*\d+,\s*\d+\]\s*\z/s, buf)
    size, gen, count = eval(buf)
    assert_operator size, :>=, 10000
    assert_operator gen, :>=, count

    cmd = @@cmd + %w(
      -e count=GC.count
      -e locs=""
      -e Mwrap.each(1){|loc,tot,calls|locs<<loc}
      -e m=locs.match(/(\[0x[a-f0-9]+\])/i)
      -e m||=locs.match(/\b(0x[a-f0-9]+)\b/i)
      -e p(loc=Mwrap["bobloblaw\t#{m[1]}"])
      -e loc.each{|size,gen|p([size,gen,count])}
    )
    buf = IO.popen(@@env, cmd, &:read)
    assert_predicate $?, :success?
    assert_match(/\bMwrap::SourceLocation\b/, buf)
  end

  def test_benchmark
    cmd = @@cmd + %w(-rbenchmark
      -e puts(Benchmark.measure{1000000.times{Time.now}}))
    r = IO.popen(@@env, cmd, 'r')
    require 'benchmark'
    warn Benchmark::Tms::CAPTION
    warn r.read
  end if ENV['BENCHMARK']

  def test_mwrap_dump_check
    assert_raise(TypeError) { Mwrap.dump(:bogus) }
  end

  def assert_separately(src, *opts)
    Tempfile.create(%w(mwrap .rb)) do |tmp|
      tmp.write(src.lstrip!)
      tmp.flush
      assert(system(@@env, *@@cmd, tmp.path, *opts))
    end
  end

  def test_source_location
    assert_separately(+"#{<<~"begin;"}\n#{<<~'end;'}")
    begin;
      require 'mwrap'
      foo = '0' * 10000
      k = -"#{__FILE__}:2"
      loc = Mwrap[k]
      loc.name == k or abort 'SourceLocation#name broken'
      loc.total >= 10000 or abort 'SourceLocation#total broken'
      loc.frees == 0 or abort 'SourceLocation#frees broken'
      loc.allocations == 1 or abort 'SourceLocation#allocations broken'
      seen = false
      loc.each do |*x| seen = x end
      seen[1] == loc.total or 'SourceLocation#each broken'
      foo.clear

      # wait for call_rcu to perform real_free
      freed = false
      until freed
        freed = true
        loc.each do freed = false end
      end
      loc.frees == 1 or abort 'SourceLocation#frees broken (after free)'
      Float === loc.mean_lifespan or abort 'mean_lifespan broken'
      Integer === loc.max_lifespan or abort 'max_lifespan broken'

      addr = false
      Mwrap.each do |a,|
        if a =~ /0x[a-f0-9]+/
          addr = a
          break
        end
      end
      addr && addr.frozen? or abort 'Mwrap.each returned unfrozen address'
      loc = Mwrap[addr] or abort "Mwrap[#{addr}] broken"
      addr == loc.name or abort 'SourceLocation#name works on address'
      loc.name.frozen? or abort 'SourceLocation#name not frozen'
    end;
  end

  def test_quiet
    assert_separately(+"#{<<~"begin;"}\n#{<<~'end;'}")
    begin;
      require 'mwrap'
      before = __LINE__
      res = Mwrap.quiet do |depth|
        depth == 1 or abort 'depth is not 1'
        ('a' * 10000).clear
        Mwrap.quiet { |d| d == 2 or abort 'depth is not 2' }
        :foo
      end
      after = __LINE__ - 1
      (before..after).each do |lineno|
        Mwrap["#{__FILE__}:#{lineno}"] and
          abort "unexpectedly tracked allocation at line #{lineno}"
      end
      res == :foo or abort 'Mwrap.quiet did not return block result'
    end;
  end

  def test_total_bytes
    assert_separately(+"#{<<~"begin;"}\n#{<<~'end;'}")
    begin;
      require 'mwrap'
      Mwrap.total_bytes_allocated > 0 or abort 'nothing allocated'
      Mwrap.total_bytes_freed > 0 or abort 'nothing freed'
      Mwrap.total_bytes_allocated > Mwrap.total_bytes_freed or
        abort 'freed more than allocated'
    end;
  end

  def test_heap_page_body
    assert_separately(+"#{<<~"begin;"}\n#{<<~'end;'}")
    begin;
      require 'mwrap'
      require 'rubygems' # use up some memory
      ap = GC.stat(:heap_allocated_pages)
      h = {}
      nr = 0
      Mwrap::HeapPageBody.each do |addr, gen|
        nr += 1
        gen <= GC.count && gen >= 0 or abort "bad generation: #{gen}"
        (0 == (addr & 16383)) or abort "addr not aligned: #{'%x' % addr}"
      end
      nr == ap or abort 'HeapPageBody.each missed page'
      10.times { (1..20000).to_a.map(&:to_s) }
      3.times { GC.start }
      Mwrap::HeapPageBody.stat(h)
      Integer === h[:lifespan_max] or abort 'lifespan_max not recorded'
      Integer === h[:lifespan_min] or abort 'lifespan_min not recorded'
      Float === h[:lifespan_mean] or abort 'lifespan_mean not recorded'
      3.times { GC.start }
      10.times { (1..20000).to_a.map(&:to_s) }
      Mwrap::HeapPageBody.stat(h)
      h[:deathspan_min] <= h[:deathspan_max] or
        abort 'wrong min/max deathtime'
      Float === h[:deathspan_mean] or abort 'deathspan_mean not recorded'
    end;
  end
end
