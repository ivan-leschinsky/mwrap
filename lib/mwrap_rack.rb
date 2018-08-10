# Copyright (C) 2018 all contributors <mwrap@80x24.org>
# License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
# frozen_string_literal: true
require 'mwrap'
require 'rack'
require 'cgi'

# MwrapRack is a standalone Rack application which can be
# mounted to run within your application process.
#
# Using the Rack::Builder API in config.ru, you can map it to
# the "/MWRAP/" endpoint.  As with the rest of the Mwrap API,
# your Rack server needs to be spawned with the mwrap(1)
# wrapper to enable the LD_PRELOAD.
#
#     require 'mwrap_rack'
#     map('/MWRAP') { run(MwrapRack.new) }
#     map('/') { run(your_normal_app) }
#
# A live demo is available at https://80x24.org/MWRAP/
# (warning the demo machine is 32-bit, so counters will overflow)
#
# This module is only available in mwrap 2.0.0+
class MwrapRack
  module HtmlResponse # :nodoc:
    def response
      [ 200, {
          'Expires' => 'Fri, 01 Jan 1980 00:00:00 GMT',
          'Pragma' => 'no-cache',
          'Cache-Control' => 'no-cache, max-age=0, must-revalidate',
          'Content-Type' => 'text/html; charset=UTF-8',
        }, self ]
    end
  end

  class Each < Struct.new(:script_name, :min, :sort) # :nodoc:
    include HtmlResponse
    HEADER = '<tr><th>' + %w(total allocations frees mean_life max_life
                location).join('</th><th>') + '</th></tr>'
    FIELDS = %w(total allocations frees mean_life max_life location)
    def each
      Mwrap.quiet do
        t = -"Mwrap.each(#{min})"
        sn = script_name
        all = []
        f = FIELDS.dup
        sc = FIELDS.index(sort || 'total') || 0
        f[sc] = -"<b>#{f[sc]}</b>"
        f.map! do |hdr|
          if hdr.start_with?('<b>')
            hdr
          else
            -%Q(<a\nhref="#{sn}/each/#{min}?sort=#{hdr}">#{hdr}</a>)
          end
        end
        Mwrap.each(min) do |loc, total, allocations, frees, age_sum, max_life|
          mean_life = frees == 0 ? Float::INFINITY : age_sum/frees.to_f
          all << [total,allocations,frees,mean_life,max_life,loc]
        end
        all.sort_by! { |cols| -cols[sc] }

        yield(-"<html><head><title>#{t}</title></head>" \
               "<body><h1>#{t}</h1>\n" \
               "<h2>Current generation: #{GC.count}</h2>\n<table>\n" \
               "<tr><th>#{f.join('</th><th>')}</th></tr>\n")
        all.each do |cols|
          loc = cols.pop
          cols[3] = sprintf('%0.3f', cols[3]) # mean_life
          href = -(+"#{sn}/at/#{CGI.escape(loc)}").encode!(xml: :attr)
          yield(%Q(<tr><td>#{cols.join('</td><td>')}<td><a\nhref=#{
                  href}>#{-loc.encode(xml: :text)}</a></td></tr>\n))
          cols.clear
        end.clear
        yield "</table></body></html>\n"
      end
    end
  end

  class EachAt < Struct.new(:loc) # :nodoc:
    include HtmlResponse
    HEADER = '<tr><th>size</th><th>generation</th></tr>'

    def each
      t = loc.name.encode(xml: :text)
      yield(-"<html><head><title>#{t}</title></head>" \
             "<body><h1>live allocations at #{t}</h1>" \
             "<h2>Current generation: #{GC.count}</h2>\n<table>#{HEADER}")
      loc.each do |size, generation|
        yield("<tr><td>#{size}</td><td>#{generation}</td></tr>\n")
      end
      yield "</table></body></html>\n"
    end
  end

  class HeapPages # :nodoc:
    include HtmlResponse
    HEADER = '<tr><th>address</th><th>generation</th></tr>'

    def hpb_rows
      Mwrap::HeapPageBody.stat(stat = Thread.current[:mwrap_hpb_stat] ||= {})
      %i(lifespan_max lifespan_min lifespan_mean lifespan_stddev
         deathspan_max deathspan_min deathspan_mean deathspan_stddev
         resurrects
        ).map! do |k|
         "<tr><td>#{k}</td><td>#{stat[k]}</td></tr>\n"
      end.join
    end

    def gc_stat_rows
      GC.stat(stat = Thread.current[:mwrap_gc_stat] ||= {})
      %i(count heap_allocated_pages heap_eden_pages heap_tomb_pages
          total_allocated_pages total_freed_pages).map do |k|
         "<tr><td>GC.stat(:#{k})</td><td>#{stat[k]}</td></tr>\n"
      end.join
    end

    GC_STAT_URL = 'https://docs.ruby-lang.org/en/trunk/GC.html#method-c-stat'
    GC_STAT_HELP = <<~""
      <p>Non-Infinity lifespans can indicate fragmentation.
      <p>See <a
      href="#{GC_STAT_URL}">#{GC_STAT_URL}</a> for info on GC.stat values.

    def each
      Mwrap.quiet do
        yield("<html><head><title>heap pages</title></head>" \
              "<body><h1>heap pages</h1>" \
              "<table><tr><th>stat</th><th>value</th></tr>\n" \
              "#{hpb_rows}" \
              "#{gc_stat_rows}" \
              "</table>\n" \
              "#{GC_STAT_HELP}" \
              "<table>#{HEADER}")
        Mwrap::HeapPageBody.each do |addr, generation|
          addr = -sprintf('0x%x', addr)
          yield(-"<tr><td>#{addr}</td><td>#{generation}</td></tr>\n")
        end
        yield "</table></body></html>\n"
      end
    end
  end

  def r404 # :nodoc:
    [404,{'Content-Type'=>'text/plain'},["Not found\n"]]
  end

  # The standard Rack application endpoint for MwrapRack
  def call(env)
    case env['PATH_INFO']
    when %r{\A/each/(\d+)\z}
      min = $1.to_i
      m = env['QUERY_STRING'].match(/\bsort=(\w+)/)
      Each.new(env['SCRIPT_NAME'], min, m ? m[1] : nil).response
    when %r{\A/at/(.*)\z}
      loc = -CGI.unescape($1)
      loc = Mwrap[loc] or return r404
      EachAt.new(loc).response
    when '/heap_pages'
      HeapPages.new.response
    when '/'
      n = 2000
      u = 'https://80x24.org/mwrap/README.html'
      b = -('<html><head><title>Mwrap demo</title></head>' \
          "<body><p><a href=\"each/#{n}\">allocations &gt;#{n} bytes</a>" \
          "<p><a href=\"#{u}\">#{u}</a>" \
          "<p><a href=\"heap_pages\">heap pages</a>" \
          "</body></html>\n")
      [ 200, {'Content-Type'=>'text/html','Content-Length'=>-b.size.to_s},[b]]
    else
      r404
    end
  end
end
