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
create_makefile 'mwrap'
