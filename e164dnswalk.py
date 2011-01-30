#!/usr/bin/env python
# encoding: utf-8
#
#	e164dnswalk - walks e164.arpa tree for a given phone number prefix
#
#	Copyright ©2011 Simon Arlott
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License v2
#	as published by the Free Software Foundation.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#	Or, point your browser to http://www.gnu.org/copyleft/gpl.html

from __future__ import print_function
import argparse
import dns.exception
import dns.resolver
import re
import sys

decimals = [str(i) for i in range(0, 10)]
res = dns.resolver.Resolver()

def to_number(number):
	return "".join(list(reversed(number)))

def walk(zone, arpa, verbose=False, timeout=False):
	global res
	numbers = {}
	for decimal in decimals:
		try:
			number = [decimal] + zone

			if verbose:
				print("".join(reversed(number)), file=sys.stderr, end=" ")

			answers = res.query(".".join(number + arpa), "NAPTR")

			if verbose:
				count = len(answers)
				print("{0} NAPTR RR{1}".format(count, "" if count == 1 else "s"), file=sys.stderr)

			numbers[to_number(number)] = [naptr.to_text() for naptr in answers]
		except dns.resolver.NoAnswer:
			if verbose:
				print("NoAnswer", file=sys.stderr)

			if len(number) < 15:
				numbers.update(walk(number, arpa, verbose, timeout))
		except dns.resolver.NXDOMAIN:
			if verbose:
				print("NXDOMAIN", file=sys.stderr)
		except dns.exception.Timeout:
			if timeout:
				print("".join(reversed(number)) + " Timeout", file=sys.stderr)
				sys.exit(1)
			if verbose:
				print("Timeout", file=sys.stderr)
	return numbers

def from_prefix(parser, args):
	if not re.match("^[0-9]*$", args.prefix):
		parser.error("Invalid phone number")

	return list(reversed(list(args.prefix)))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Walks e164.arpa tree for a given phone number prefix')
	parser.add_argument('-p', '--parent', default='e164.arpa', help='Use specified parent')
	parser.add_argument('-r', '--resolver', action='append', help='Use specified resolver(s)')
	parser.add_argument('-t', '--timeout', action='store_true', help='Abort on timeout')
	parser.add_argument('-v', '--verbose', action='store_true', help='Outputs every NAPTR query performed to stderr')
	parser.add_argument('prefix', help='Phone number prefix')
	args = parser.parse_args()

	if args.resolver is not None:
		res = dns.resolver.Resolver(configure=False)
		res.nameservers = args.resolver

	numbers = walk(from_prefix(parser, args), [args.parent + "."], args.verbose, args.timeout)
	for number in sorted(numbers.keys()):
		for record in sorted(numbers[number]):
			print(number, record)

	parser.exit()
