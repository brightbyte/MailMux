import poplib, imaplib, smtplib
import email, email.parser, email.message, email.header, rfc822
import sys, os, os.path, re, datetime, time
import imp, pickle, argparse
import pprint, traceback

class Filter:
	def matches( self, msg ):
		raise Exception("not implemented")
		
	def __str__( self ):
		return type(self)

class Yes (Filter):
	def matches( self, msg ):
		return True

	def __str__( self ):
		return "Yes"
		
class And (Filter):
	def __init__(self, *filters):
		self.filters = filters

	def matches( self, msg ):
		for f in self.filters:
			if not f.matches( msg ):
				return False
		
		return True

	def __str__( self ):
		return "( " + reduce( lambda s, t: "%s and %s" % (s, t), self.filters ) + " )"
		
class Not (Filter):
	def __init__(self, filter):
		self.filter = filter

	def matches( self, msg ):
		return not self.filter.matches(msg)
		
	def __str__( self ):
		return "Not %s" % self.filter

class Or (Filter):
	def __init__(self, *filters):
		self.filters = filters

	def matches( self, msg ):
		for f in self.filters:
			if f.matches( msg ):
				return True
		
		return False

	def __str__( self ):
		return "( " + reduce( lambda s, t: "%s or %s" % (s, t), self.filters ) + " )"
		
class HeaderFilter (Filter):
	def __init__(self, header):
		self.header = header
				
	def matches( self, msg ):
		#TODO: allow access to xx_vars here!
		
		if self.header.startswith("xx_"):
			try:
				hh = getattr( msg, self.header )
			except:
				hh = None
		else:
			hh = msg.get_all(self.header)
		
		if not type(hh) in (tuple, list, set):
			hh = ( hh, )
		
		if hh: 
			for h in hh:
				h = decode_header_str( h )
				if self.matches_value( h ):
					return True
					
		return False

	def matches_value( self, v ):
		return Exception("not implemented")
		
class Matches  (HeaderFilter):
	def __init__(self, header, regex, flags = 0):
		HeaderFilter.__init__(self, header)
		
		if type(regex) == str or type(regex) == unicode:
			self.regex = re.compile(regex, flags)
		else:
			self.regex = regex
		
	def matches_value( self, v ):
		if v.startswith('^'):
			m = self.regex.match( v )
		else:
			m = self.regex.search( v )
		
		if m: return True
		else: return False
		
	def __str__( self ):
		return "%s ~~ %s" % (self.header, self.regex.pattern)
		
class Equals (HeaderFilter):
	def __init__(self, header, value):
		HeaderFilter.__init__(self, header)
		self.value = value
		
	def matches_value( self, v ):
		return v == self.value
		
	def __str__( self ):
		return "%s == %s" % (self.header, self.value)
		
class HasTag (Equals):
	def __init__(self, tag):
		Equals.__init__(self, "xx_flags", tag)
	
class Contains (Matches):
	def __init__(self, header, value, case_sensitive = False):
		if case_sensitive:
			f = rs.CASE_SENSITIVE
		else:
			f = 0
			
		if type(value) != str:
			p = "(" + "|".join( map( lambda s: re.escape(s), value ) ) + ")"
		else:
			p = re.escape(value)
			
		Matches.__init__(self, header, '.*' + p + '.*', f)
		
class Greater (HeaderFilter):
	def __init__(self, header, value):
		HeaderFilter.__init__(self, header)
		self.value = value
		
	def matches_value( self, v ):
		return v > self.value
		
	def __str__( self ):
		return "%s > %s" % (self.header, self.value)
		
class Less (HeaderFilter):
	def __init__(self, header, value):
		HeaderFilter.__init__(self, header)
		self.value = value
		
	def matches_value( self, v ):
		return v < self.value
		
	def __str__( self ):
		return "%s < %s" % (self.header, self.value)

class Older (HeaderFilter):
	def __init__(self, header, age):
		HeaderFilter.__init__(self, header)
		
		if type(age) == str or type(age) == unicode:
			if age.endswith("y"):
				age = int(age[:-1]) * 365 * 24 * 60 * 60
			elif age.endswith("w"):
				age = int(age[:-1]) * 7 * 24 * 60 * 60
			elif age.endswith("d"):
				age = int(age[:-1]) * 24 * 60 * 60
			elif age.endswith("h"):
				age = int(age[:-1]) * 60 * 60
			elif age.endswith("m"):
				age = int(age[:-1]) * 60
			elif age.endswith("s"):
				age = int(age);
			else:
				age = int(age) * 24 * 60 * 60;
			
		self.age = age
		
	def matches_value( self, v ):
		t0 = time.time()

		then = rfc822.parsedate_tz( v )
		t1 = rfc822.mktime_tz(then)
		
		return (t0 - t1) > self.age
		
	def __str__( self ):
		return "%s older than %s seconds" % (self.header, self.value)
