# frozen_string_literal: true
# Copyright (C) 2018 mwrap hackers <mwrap-public@80x24.org>
# License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
require 'mkmf'

have_func 'mempcpy'
if RUBY_PLATFORM =~ /linux/ # should detect glibc
  if File.read("/proc/#$$/maps") =~ /\blibjemalloc\./
    $defs << '-DRUBY_USES_JEMALLOC'
  end
end
have_library 'dl'
create_makefile 'mwrap'
