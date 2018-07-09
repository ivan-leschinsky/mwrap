# frozen_string_literal: true
# Copyright (C) 2018 mwrap hackers <mwrap-public@80x24.org>
# License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
require 'mkmf'

have_func 'mempcpy'
have_library 'urcu-cds' or abort 'userspace RCU not installed'
have_header 'urcu/rculfhash.h' or abort 'rculfhash.h not found'
have_library 'urcu-bp' or abort 'liburcu-bp not found'
have_library 'dl'
have_library 'c'
have_library 'execinfo' # FreeBSD

if try_link(<<'')
int main(void) { return __builtin_add_overflow_p(0,0,(int)1); }

  $defs << '-DHAVE_BUILTIN_ADD_OVERFLOW_P'
end

if try_link(<<'')
int main(int a) { return __builtin_add_overflow(0,0,&a); }

  $defs << '-DHAVE_BUILTIN_ADD_OVERFLOW_P'
else
  abort 'missing __builtin_add_overflow'
end

create_makefile 'mwrap'
