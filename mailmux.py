import poplib, imaplib, smtplib
import email, email.parser, email.message, email.header, rfc822
import sys, os, os.path, re, datetime, time
import imp, pickle, argparse
import pprint, traceback

ABORT = "*abort*"
SEEN = "*seen*"
DELETE = "*delete*"

FORWARD = "*forward*"
TRANSFER = "*transfer*"
MOVE = "*move*"
COPY = "*copy*"
FLAG = "*flag*"
TAG = "*tag*"

class Action (object):
	def __init__(self, atype):
		self.atype = atype
		
	def __str__(self):
		return self.atype
		
class Dump (Action):
	def __init__(self):
		Action.__init__(self, "*dump*")
		
	def perform(self, msg, service):
		print msg_unicode( msg ).encode( "utf-8" ) #XXX: make charset configurable
		print ""
		
class DumpHeaders (Action):
	def __init__(self, *headers ):
		Action.__init__(self, "*dump-headers*")
		self.headers = headers
		
	def perform(self, msg, service):
		for h in self.headers:
			vv = msg.get_all(h)
			
			if vv:
				for v in vv:
					print "%s: %s" % (h, v)
		print ""
		
class Forward (Action):
	def __init__(self, dest, service = None):
		Action.__init__(self, FORWARD)
		self.dest = dest
		self.service = service

	def __str__(self):
		return self.atype + " to " + self.dest
		
class Move (Action):
	def __init__(self, folder):
		Action.__init__(self, MOVE)
		self.folder = folder

	def __str__(self):
		return self.atype + " to " + self.folder		
		
class Copy (Action):
	def __init__(self, folder):
		Action.__init__(self, COPY)
		self.folder = folder

	def __str__(self):
		return self.atype + " to " + self.folder
		
class Transfer (Action):
	def __init__(self, service, folder = "INBOX"):
		Action.__init__(self, TRANSFER)
		self.service = service
		self.folder = folder

	def __str__(self):
		return self.atype + " to " + self.folder + " on " + self.service
				
class Tag (Action):
	def __init__(self, tags):
		Action.__init__(self, TAG)
		self.tags = tags
		
	def __str__(self):
		return self.atype + " with " + self.tags
				
abort_action = Action(ABORT)
seen_action = Action(SEEN)
delete_action = Action(DELETE)
flag_action = Action(FLAG)

dump_action = Dump()
list_action = DumpHeaders("Message-Id", "Subject", "From", "To", "Envelope-to", "Date")
		
		
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

# --------------------------------------------------------------------------------------------
def trace(msg):
	if debug:
		if type( msg ) == unicode:
			msg = msg.encode( "utf-8" ) #XXX: make charset configurable
		
		print msg

def log(msg):
	if not quiet:
		if type( msg ) == unicode:
			msg = msg.encode( "utf-8" ) #XXX: make charset configurable
		
		print msg

def complain(msg):
	if type( msg ) == unicode:
		msg = msg.encode( "utf-8" ) #XXX: make charset configurable
	
	print msg

class MailService (object):
	def __init__(self, **connection_spec):
		self.connection_spec = connection_spec
		self.connection = None
		self.dry = False

	def open(self):
		self.connection = self.connect_to(**self.connection_spec)

	def close(self):
		raise Exception("unimplemented")
		
	#---------------------------------------------

	def unwrap(self, re):
		return re
		
	def connect_to(self, *spec):
		raise Exception("unimplemented")
		

class MailboxService (MailService):
	def list_mailboxes(self):
		raise Exception("unimplemented")
		
	def get_continuation(self, msg, prev_continue = None):
		try:
			d = msg.xx_date_received
		except:
			d = msg["Date"]
			
		if prev_continue and 'since' in prev_continue:
			t = as_datetime( prev_continue['since'] )
			
			if t > d:
				d = t
			
		since = d.__str__()
		return { 'since': since }
		
	def list_messages(self, max_messages = None, mailbox = "INBOX", **options ):
		raise Exception("unimplemented")

	def peek_headers(self, id):
		raise Exception("unimplemented")
		
	def fetch_message(self, id, peek = False):
		raise Exception("unimplemented")
		
	def delete_message(self, id):
		raise Exception("unimplemented")

	def apply_actions( self, id, msg, actions ):
		atypes = get_action_types( actions )
		
		if len(atypes) == 0 or ( len(atypes) == 1 and iter(atypes).next() == ABORT ): 
			return #shorten out
			
		if self.dry: 
			log( u"ACTIONS FOR %s" % msg_unicode(msg) )
			log( u"  ACTION TYPES: %s" % atypes )

		if not self.dry:
			if SEEN in atypes or FORWARD in atypes or TRANSFER in atypes:
				peek = (not SEEN in atypes)
				if peek:
					trace( "LOADING MSG %s IN PEEK MODE" % (id,) )
				else: 
					trace( "RECEIVING MSG %s AND MARKING AS SEEN" % (id,) )
				
				msg = self.fetch_message( id, peek )
				has_body = True
				
		for a in actions:
			if self.dry:
				if a.atype == ABORT:
					break
					
				log("  %s" % a);
				continue
				
			if a.atype == SEEN:
				pass # already handled
				
			elif a.atype == DELETE:
				pass # handled later
				
			elif a.atype == ABORT:
				break
				
			elif a.atype == FORWARD:
				fwd_msg = make_forward_message(msg, a.dest)
				
				if a.service:
					srv = services[a.service]
				else:
					srv = services["smtp"]
					
				log( u"FORWARDING %s ==> %s" % (msg_unicode(msg), a.dest) )
				srv.send_message( fwd_msg )
					
			elif a.atype == TRANSFER:
				log( u"TRANSFERING %s ==> %s/%s" % (msg_unicode(msg), a.service, a.folder) )
				srv = services[ a.service ]
				srv.add_message( msg, a.folder ) #NOTE: only works with imap service
					
			elif a.atype == COPY:
				log( u"COPYING %s ==> %s" % (msg_unicode(msg), a.folder) )
				self.copy_message( id, a.folder ) #NOTE: only works with imap service
					
			elif a.atype == MOVE:
				log( u"MOVING %s ==> %s" % (msg_unicode(msg), a.folder) )
				self.move_message( id, a.folder ) #NOTE: only works with imap service
					
			elif a.atype == FLAG:
				log( u"FLAGGING %s" % (msg_unicode(msg)) )
				self.update_flags( id, '\Flagged' ) #XXX: this is imap-specific
					
			elif a.atype == TAG:
				if not type(a.tags) == str and not type(a.tags) == unicode:
					f = " ".join(a.tags)
				else:
					f = a.tags
				
				log( u"TAGGING %s WITH %s" % (msg_unicode(msg), f) )
				self.update_flags( id, f )
			else:
				try:
					a.perform( msg, self )
				except AttributeError:
					raise Exception("Unknown action type `%s`; custom actions must implement method perform(Message, MailService)" % a.atype)
					
		if not self.dry:
			if DELETE in atypes:
				log( u"DELETING %s" % (msg_unicode(msg),) )
				self.delete_message( id )
				
	def process_messages(self, filters, since = None, max_messages = None, mailbox = "INBOX", persist = None):
		if since:
			# override continuation
			continuation = { 'since': since }
			trace( "PROCESSING MESSAGES SINCE %s" % since );
		elif persist is not None:
			continuation = persist.get("continuation")
			
			if continuation:
				trace( "PROCESSING MESSAGES FROM CONTINUATION MARKER: %s" % continuation );
			else:
				trace( "PROCESSING MESSAGES (NO CONTINUATION FOUND)" );
				continuation = {}
		else:
			continuation = {}
			trace( "PROCESSING ALL MESSAGES" );
				
	
		messages = self.list_messages(max_messages = max_messages, mailbox = mailbox, **continuation)
		
		if not messages or len(messages) == 0:
			return
		
		trace( "PROCESSING %i MESSAGES" % len(messages) );

		for id, msg in messages.items():
			actions = get_message_actions( msg, filters )
			
			if actions:
				try:
					self.apply_actions( id, msg, actions )
				except Exception, e:
					complain( u"ERROR: Failed to apply actions to %s: %s " % (msg_unicode(msg), e ) )

			if persist is not None:
				continuation = self.get_continuation( msg, continuation )

		if persist is not None and continuation:
			trace("PERSISTING CONTINUATION MARKER: %s" % continuation)
			persist["continuation"] = continuation
			
	def add_message(self, msg, folder):
		raise Exception("unimplemented, not a directory service")

	def move_message(self, id, folder):
		raise Exception("unimplemented, not a directory service")

	def copy_message(self, id, folder):
		raise Exception("unimplemented, not a directory service")

	def update_flags(self, id, flags):
		raise Exception("unimplemented, not a directory service")

class MailTransportService (MailService):
	
	def send_messages(self, messages):
		for msg in messages:
			fromaddr = msg["From"]
			
			toaddrs = msg.get_all("Envelope-to")
			if not toaddrs or len(toaddrs) == 0:
				toaddrs = msg.get_all("To")
				cc = msg.get_all("Cc")
				bcc = msg.get_all("Bcc")
				
				if cc: toaddrs.extend( cc )
				if bcc: toaddrs.extend( bcc ) #XXX: how to handle this correctly? Unset header?
				
			self.send_message_to( fromaddr, toaddrs, msg )
		
	def send_message(self, msg, toaddrs = None, fromaddr = None):
		if not fromaddr:
			fromaddr = msg["From"]
		
		if not toaddrs:
			toaddrs = msg.get_all("Envelope-to")
			if not toaddrs or len(toaddrs) == 0:
				toaddrs = msg.get_all("To")
				cc = msg.get_all("Cc")
				bcc = msg.get_all("Bcc")
				
				if cc: toaddrs.extend( cc )
				if bcc: toaddrs.extend( bcc ) #XXX: how to handle this correctly? Unset header?
				
		self.send_message_to(fromaddr, toaddrs, msg)
			
		
	def send_message_to(self, fromaddr, toaddrs, msg):
		raise Exception("unimplemented")
		
class Pop3Service ( MailboxService ):
	def __init__(self, **connection_spec):
		MailService.__init__(self, **connection_spec)

	def unwrap( self, response ):
		if type(response) != str:
			code = response[0]
			content = response[1]
		else:
			code = response
			content = response
		
		if not code.startswith( "+OK" ):
			raise Exception("POP3 error: %s" % content)
			
		return content
		
	def connect_to( self,
					host, user, password, 
					protocol = "pop3", security = None, auth = None, 
					port = None, timeout = None, 
					keyfile = None, certfile = None ):
								
		if not security: 
			if not port: port = 110

			trace( "CONNECTING TO POP3 %s@%s:%i" % (user, host, port) )
			conn = poplib.POP3( host, port, timeout )

		elif security == 'ssl': 
			if not port: port = 995

			trace( "CONNECTING TO POP3/SSL %s@%s:%i" % (user, host, port) )
			conn = poplib.POP3_SSL( host, port, timeout )

		else: raise Exception("unknown security mode: %s", security) 

		welcome = self.unwrap( conn.getwelcome() )
		
		if not auth: 
			conn.user(user)
			conn.pass_(password)
		elif auth == "rpop":
			conn.rpop(user)
		elif auth == "apop":
			conn.apop(user, password)
		else: 
			raise Exception("unknown auth method: %s", security) 
		
		return conn
			
	def close(self):
		if self.connection:
			self.connection.quit()
			self.connection = None		
			
	def list_mailboxes(self):
		return [ "INBOX" ]
		
	def list_messages(self, max_messages = None, mailbox = "INBOX", **options ):
		if 'since' in options: since = options['from_uid']
		else: since = None
		
		(num, size) = self.connection.stat()
		
		# fetch the newest n = max_messages messages
		to_no = num
		
		if not max_messages:
			from_no = 1
		else:
			from_no = num - max_messages +1;
			if from_no < 1: from_no = 1;

		trace( "FETCHING MSG NO %i to %i" % (from_no, to_no) )
		
		if since:
			since = as_datetime( since )
			
		#XXX: if "since" is set, use binary search to find first message!
		
		messages = {}
		for no in range(from_no, to_no+1):
			msg = self.peek_headers(no)
			
			if since: 
				if msg["Date"]:
					d = as_datetime( rfc822.parsedate_tz( msg["Date"] ) ) #XXX: would be nice to use the date the mail was *received*
					
					if not d < since:
						#print "%s == %s < %s " % (d, msg["Date"], since)
						since = None
					else:
						continue
				else:
					continue
			
			messages[no] = msg
		
		return messages

	def peek_headers(self, id):
		re = self.unwrap( self.connection.top(id, 0) )
		
		raw = "\r\n".join( re )
		msg = rfc822parser.parsestr( raw, True )
		
		return msg
		
	def fetch_message(self, id, peek = False):
		if peek:
			re = self.unwrap( self.connection.top(id, 2**31-1) )
		else:
			re = self.unwrap( self.connection.retr(id) )
		
		raw = "\r\n".join( re )
		msg = rfc822parser.parsestr( raw, True )
		
		return msg
		
	def delete_message(self, id):
		self.unwrap( self.connection.delete(id) )
	
imap_part_pattern = re.compile( r'\s*([\w]+)|\s*"(.*?)"|\s*\((.*?)\)|\s*\{(\d+)\}\r\n' )
alphanumeric_pattern = re.compile( r'\w+' )
whitespace_pattern = re.compile( r'\s+' )
	
def imap_split( s ):
	i = 0
	parts = []
	
	while i<len(s):
		m = imap_part_pattern.match(s, i)
		if not m:
			raise Exception("can't parse line as IMAP tokens: %s" % s)
			
		if m.group(4) is not None:
			n = int(m.group(4))
			a = m.span()[1]
			
			i = a + n
			p = s[a:i]
			
		elif m.group(3) is not None:
			p = m.group(3)
			i = m.span()[1]
		elif m.group(2) is not None:
			p = m.group(2)
			i = m.span()[1]
		elif m.group(1) is not None:
			p = m.group(1)
			i = m.span()[1]

		parts.append(p)
		
	return tuple(parts)

month = (
	'-',
	'Jan',
	'Feb',
	'Mar',
	'Apr',
	'May',
	'Jun',
	'Jul',
	'Aug',
	'Sep',
	'Oct',
	'Nov',
	'Dec',
)

def as_imap_date( d, with_time = False ):
	if d.tzinfo:
		tzd = d.tzinfo.utcoffset( d )
	else:
		tzd = tz.utcoffset( d )
		
	ofs = tzd.total_seconds()
	hofs = abs( ofs / 3600 )
	mofs = abs( ofs - ( hofs * 3600 ) ) / 60 
	
	if with_time:
		return "%2i-%s-%04i %02i:%02i:%02i %s%02i%02i" % (d.day, month[d.month], d.year, d.hour, d.minute, d.second, 
															'+' if ofs > 0 else '-', hofs, mofs )
	else:
		return "%2i-%s-%04i" % ( d.day, month[d.month], d.year )

def as_imap_date_time( d ):
	return as_imap_date( d, True )

class Imap4Service ( MailboxService ):
	def __init__(self, **connection_spec):
		MailService.__init__(self, **connection_spec)
		
		self.mailbox = None
		self.caps = None
		
	#FIXME: use uid commands

	def unwrap( self, response ):
		if not response:
			return response
		
		if response[0] != "OK" :
			#pprint.pprint(response)
			raise Exception( "IMAP4 error: %s" % " ".join(response[1]) )
			
		return response[1]

	def open(self):
		MailService.open(self)
		
		if "charset" in self.connection_spec:
			self.charset = self.connection_spec['charset']
		else:
			self.charset = "utf-8"
			
		self.caps = self.unwrap( self.connection.capability() )
		#pprint.pprint( self.caps )

		self.folders = self.unwrap( self.connection.list() )
		#pprint.pprint( self.folders )
			

	def connect_to( self,
					host, user, password, 
					protocol = "imap4", security = None, 
					timeout = None, auth = None, auth_handler = None,
					port = None, mailbox = None, 
					keyfile = None, certfile = None,
					charset = "utf-8" ):
						
		if not mailbox:
			mailbox = "INBOX"
														
		if not security: 
			if not port: port = 143

			trace( "CONNECTING TO IMAP4 %s@%s:%i" % (user, host, port) )
			conn = imaplib.IMAP4( host, port )

		elif security == 'ssl': 
			if not port: port = 993

			trace( "CONNECTING TO IMAP4/SSL %s@%s:%i" % (user, host, port) )
			conn = imaplib.IMAP4_SSL( host, port, keyfile, certfile )

		else: raise Exception("unknown security mode: %s", security) 

		#mail.debug = 10

		if auth and auth_handler:
			self.unwrap( conn.authenticate(auth, auth_handler) )
		elif not auth:
			self.unwrap( conn.login(user, password) )
		elif auth in ("cram", "cram_md5", "cram-md5", "md5"):
			self.unwrap( conn.login_cram_md5(user, password) )
		else: 
			raise Exception("unknown auth method: %s", security) 
		
		return conn
		
	def close(self):
		if self.connection:
			# commit deletions if neccessary
			if self.mailbox is not None and not self.dry:
				self.unwrap( self.connection.expunge() ) 
				self.mailbox = None
			
			# disconnect imap4
			self.connection.logout()
			self.connection = None		
			
	def list_mailboxes(self):
		mailboxes = self.unwrap( self.connection.list( ) )
		return [ imap_split(x)[2] for x in mailboxes ]
		
	def get_continuation(self, msg, prev_continue = None):
		try:
			uid = msg.xx_uid
			
			if prev_continue and 'from_uid' in prev_continue:
				u = prev_continue['from_uid']
				
				if u > uid:
					uid = u
			
			return { 'from_uid': int(uid) }
		except:
			pass
			
		return super(Imap4Service, self).get_continuation( msg, prev_continue )
		
		
	def list_messages(self, max_messages = None, mailbox = "INBOX", **options ):
		if 'from_uid' in options: from_uid = options['from_uid']
		else: from_uid = None
		
		if 'since' in options: since = options['since']
		else: since = None

		if from_uid == 'None' or from_uid == '':
			log( "Bad 'from_uid' entry in continuation!" )
			from_uid = None

                if since == 'None' or since == '':
			log( "Bad 'since' entry in continuation!" )
                	since = None
		
		if self.mailbox and self.mailbox != mailbox:
			if not self.dry:
				self.unwrap( self.connection.expunge( ) )

			log( "CLOSING MAILBOX `%s` IN ORDER TO SELECT MAILBOX `%s`" % (self.mailbox, mailbox) )
			self.unwrap( self.connection.close() )
			self.mailbox = None
			
		mailbox_info = self.unwrap( self.connection.select( mailbox ) )
		self.mailbox = mailbox
		
		if from_uid:
			if since:
				log( "IGNORING since-date, because from_uid is given" )
				
			re = self.unwrap( self.connection.uid( "SEARCH", "(UID %s:*)" % from_uid ) )
		elif since:
			since = as_datetime( since )
			t = as_imap_date( since ) 
			
			trace("searching for messages since \"%s\"" % t)
			#NOTE: IMAP disregards time and timezone when filtering by date! (yes, that's in the spec. wtf?)
			re = self.unwrap( self.connection.uid( "SEARCH", "(SINCE \"%s\")" % t ) )
		else:
			re = self.unwrap( self.connection.uid( "SEARCH", "ALL" ) )

		message_uids = re[0].split()
		
		if max_messages and len(message_uids) > max_messages:
			message_uids = message_uids[-max_messages:]
		
		if len(message_uids) == 0:
			return {}

		log( "FETCHING UID RANGE %s:%s" % (message_uids[0], message_uids[-1]) )
		#TODO: actually fetch range, not individual messages?
		
		messages = {}
		for uid in message_uids:
			trace( "fetching message %s" % str(uid) )
			msg = self.peek_headers(uid)
			
			try:
				#Skip deleted entries in IMAP inbox
				if '\\Deleted' in msg.xx_flags: 
					continue
			except:
				pass
			
			try:
				#skip UIDs we have already processed
				if from_uid and from_uid >= msg.xx_uid:
					continue
			except:
				pass
			
			messages[uid] = msg
		
		return messages

	def peek_headers(self, uid):
		re = self.unwrap( self.connection.uid('FETCH', uid, "(BODY.PEEK[HEADER] FLAGS INTERNALDATE RFC822.SIZE UID)") )
		
		msg = self.response_to_message( re )
		
		return msg
		
	def fetch_message(self, uid, peek = False):
		if peek:
			re = self.unwrap( self.connection.uid('FETCH', uid, "(BODY.PEEK[] FLAGS INTERNALDATE RFC822.SIZE UID)") )
		else:
			re = self.unwrap( self.connection.uid('FETCH', uid, "(BODY[] FLAGS INTERNALDATE RFC822.SIZE UID)") )
		
		msg = self.response_to_message( re )
		
		return msg
		
	imap_size_pattern = re.compile(r"[(\s]RFC822.SIZE\s+(\d+)[)\s]")
	imap_uid_pattern = re.compile(r"[(\s]UID\s+(\d+)[)\s]")
	imap_date_pattern = re.compile(r"[(\s]INTERNALDATE\s+\"(.*?)\"[)\s]")
	imap_flags_pattern = re.compile(r"[(\s]FLAGS\s+\((.*?)\)[)\s]")
		
	def response_to_message( self, re ):
		raw = re[0][1]
		msg = rfc822parser.parsestr( raw, True )
		
		#attach extra meta info provided by imap
		meta = re[0][0] + re[1] #WTF python?!
		
		#print "META: %s" % meta
		
		m = Imap4Service.imap_size_pattern.search(meta);
		if m:
			msg.xx_size = int(m.group(1))
		
		m = Imap4Service.imap_uid_pattern.search(meta);
		if m:
			msg.xx_uid = int(m.group(1))
		
		m = Imap4Service.imap_date_pattern.search(meta);
		if m:
			msg.xx_date_received = as_datetime(m.group(1))
		
		m = Imap4Service.imap_flags_pattern.search(meta);
		if m:
			msg.xx_flags = imaplib.ParseFlags(m.group(1))

		return msg
		
	def add_message(self, msg, folder, date = None, flags = ""):
		#XXX: use msg.xx_date_received if present??
		
		if not date:
			date = datetime.datetime.now()
			
		if isinstance(date, datetime.datetime):
			trace( "converting datetime %s" % date )
			date = as_imap_date_time( date )
			
		if isinstance(date, str) and not quoted_string_pattern.match( date ):
			date = '"%s"' % date
			
		trace( "posting with date %s" % date )
		self.unwrap( self.connection.append(folder, flags, date, msg.as_string()) )

	def delete_message(self, uid):
		self.update_flags( uid, '\Deleted' )

	def move_message(self, uid, folder):
		self.copy_message( uid, folder )
		self.delete_message( uid )

	def copy_message(self, uid, folder):
		#FIXME: preserve keywords!
		#print "copy %s, %s" % (uid, folder)
		self.unwrap( self.connection.uid('COPY', uid, folder) )

	def update_flags(self, uid, flags):
		# hack: imaplib is too keen on quoting. according to spec, lags should never be quoted,
		#       bit imaplib forces quotes when seeing a backslapsh, as in \Deleted.
		#       We wrap the flags in parentacies to avoid this.
		if not alphanumeric_pattern.match( flags ):
			if not whitespace_pattern.search( flags ):
				flags = "(%s)" % flags
		
		self.unwrap( self.connection.uid('STORE', uid, '+FLAGS', flags) )

#TODO: implement MailTransportService based on sendmail CLI interface

class SmtpService ( MailTransportService ):
	def __init__(self, **connection_spec):
		MailService.__init__(self, **connection_spec)

	def unwrap( self, response ):
		if int(response[0]) > 400 :
			raise Exception("SMTP error: %s" % response[1])
			
		return response[1]
		
	def connect_to( self,
					host, user, password, 
					protocol = "pop3", security = None, auth = None, 
					port = None, local_domain = None, timeout = None, 
					keyfile = None, certfile = None ):
		
		if not security or security == 'tls': 
			if not port: port = 25

			trace( "CONNECTING TO SMTP %s@%s:%i" % (user, host, port) )
			conn = smtplib.SMTP( host, port, local_domain, timeout )
			
			if security and security == 'tls':
				conn.starttls(keyfile, certfile)

		elif security == 'ssl': 
			if not port: port = 465

			trace( "CONNECTING TO SMTP/SSL %s@%s:%i" % (user, host, port) )
			conn = smtplib.SMTP_SSL( host, port, local_domain, keyfile, certfile, timeout )

		else: raise Exception("unknown security mode: %s", security) 

		#mail.debug = 10

		if user:
			self.unwrap( conn.login(user, password) )
										
		conn.ehlo_or_helo_if_needed()
		
		return conn
		
	def close(self):
		if self.connection:
			self.connection.quit()
			self.connection = None		
	
	def send_message_to(self, fromaddr, toaddrs, msg):
		self.connection.sendmail(fromaddr, toaddrs, msg.as_string())
	
rfc822parser = email.parser.Parser()

# --------------------------------------------------------------------------------------------
def decode_header_part( v, enc = None ):
	if enc:
		try:
			return unicode(v, enc)
		except: 
			pass
		
	try:
		return unicode(v, 'us-ascii')
	except: 
		pass
		
	try:
		return unicode(v, 'iso-8859-15')
	except: 
		pass
		
	try:
		return unicode(v, 'utf-8')
	except: 
		pass

	
def decode_header_str( h ):
	parts = email.header.decode_header( h )
	parts = map( lambda p: decode_header_part(p[0], p[1]), parts )
	
	s = reduce( lambda s, t: s + t, parts ) 
	return s

def msg_unicode( msg ):
	subject = decode_header_str( msg['Subject'] ) 
	fromadr = decode_header_str( msg['From'] ) 
	toadr = decode_header_str( msg['To'] ) 
	date = as_datetime( msg['Date'] ) 
	
	return u"%s: \"%s\" FROM [%s] TO [%s]" % (date, subject, fromadr, toadr)

# --------------------------------------------------------------------------------------------
#imap_date_pattern = re.compile(r"\d{1,2}-[a-zA-Z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(\s+[-+]\d{2,4})?")
quoted_string_pattern = re.compile(r"\"[^\"]*\"")
simple_date_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(\s*[-+]\d{2}:?\d{2})?")
offset_pattern = re.compile(r"\s*([-+])?(\d\d):?(\d\d)")

TD_ZERO = datetime.timedelta(0)

class NaiveTZ(datetime.tzinfo):
	def __init__(self, offset, name = None):

		if type(offset) == str or type(offset) == unicode:
			m = offset_pattern.match(offset)

			if not m:
				raise Exception("bad timezone offset: %s" %offset)
			
			offset = int(m.group(2))*60 + int(m.group(3))
			
			if m.group(1) and m.group(1) == "-":
				offset = -offset
				
		if offset >= 1440:
			offset = offset % 1440
			
		if offset <= -1440:
			offset = - ( (-offset) % 1440 )

		self.__offset = datetime.timedelta(minutes = offset)
		
		if not name:
			if offset == 0:
				name = "Z"
			else:
				name = self.__offset.__str__()
			
		self.__name = name

	def utcoffset(self, dt):
		return self.__offset

	def tzname(self, dt):
		return self.__name

	def dst(self, dt):
		return TD_ZERO
		
STDOFFSET = datetime.timedelta(seconds = -time.timezone)
if time.daylight:
    DSTOFFSET = datetime.timedelta(seconds = -time.altzone)
else:
    DSTOFFSET = STDOFFSET

DSTDIFF = DSTOFFSET - STDOFFSET		
        
class LocalTZ(datetime.tzinfo):

    def utcoffset(self, dt):
        if self._isdst(dt):
            return DSTOFFSET
        else:
            return STDOFFSET

    def dst(self, dt):
        if self._isdst(dt):
            return DSTDIFF
        else:
            return ZERO

    def tzname(self, dt):
        return time.tzname[self._isdst(dt)]

    def _isdst(self, dt):
        tt = (dt.year, dt.month, dt.day,
              dt.hour, dt.minute, dt.second,
              dt.weekday(), 0, 0)
        stamp = time.mktime(tt)
        tt = time.localtime(stamp)
        return tt.tm_isdst > 0       
         
tz = LocalTZ()

def as_datetime( d ):
	trace( "Converting date: %s" % repr(d) )

	if d == 'None' or d == '': # hack for bad input
		d = None 

	if not d:
		return d
		
	if isinstance(d, datetime.datetime):
		return d
		
	elif isinstance(d, time.struct_time):
		return datetime.datetime(d.tm_year, d.tm_mon, d.tm_mday, d.tm_hour, d.tm_min, d.tm_sec, 0, tz)
		
	elif type(d) == tuple:
		if len(d)>9: # rfc822.parsedate_tz returns the time zone offset in seconds in d[9]
			zone = NaiveTZ(d[9]/60) #convert seconds to minutes
		else:
			zone = tz
			
		return datetime.datetime(d[0], d[1], d[2], d[3], d[4], d[5], d[6], zone)
		
	elif type(d) == str or type(d) == unicode:
		m = simple_date_pattern.match(d)
		
		if m:
			t = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
			
			if m.group(2):
				zone = NaiveTZ(m.group(2))
			else:
				zone = tz
				
			t = t.replace( tzinfo = zone )
			return t
		else:	
			tpl = rfc822.parsedate_tz( d )
			if tpl is None:
				raise Exception("failed to parse date using rfc822: %s" % d)
				
			t = as_datetime( tpl )
			if tpl is None:
				raise Exception("failed to create date from tupel: %s (was date: %s)" % (tpl, d))
				
			return t
			
	else:
		raise Exception("can't convert instance of type %s to a datetime object" % type(d))
		
# --------------------------------------------------------------------------------------------
	
def add_actions( actions, into ):
	if not actions:
		return into
	
	if type(actions) == type(ABORT): 
		into.append( Action(actions) )
	elif isinstance(actions, Action):
		into.append( actions )
	else: 
		for a in actions:
			if type(a) == str or type(a) == unicode: 
				a = Action(a)
				
			into.append( a )
			
			if a.atype == ABORT: 
				break
	
	return into
	
def get_message_actions( msg, filters ):
	actions = []
	
	#trace("applying filters to %s" % msg_unicode(msg) )
	
	for (f, aa) in filters:
		if f.matches(msg): 
			actions = add_actions( aa, actions )
			#trace("  matched %s, adding %s" % (f, aa) )
			
			if actions and actions[-1].atype == ABORT:
				#trace("  abort found, stop evaluating filters" )
				break
		else:
			#trace("  mismatched %s" % (f, ) )
			pass
	
	i = 0
	for a in actions:
		if a.atype == ABORT:
			break
			
		i += 1
		
	actions = actions[:i] #cut off everything after the abort
			
	if not actions:
		actions = add_actions( default_actions, actions )
		
	return actions

def get_action_types( actions ):
	types = set()
	
	for a in actions:
		types.add( a.atype )
		
		if a.atype == ABORT:
			break
	
	return types
	
def make_forward_message( msg, to ):
	#clone message
	fwd_msg = rfc822parser.parsestr( msg.as_string(), False )
	
	#manipulate headers
	if 'Envelope-to' in msg:
		fwd_msg['X-Original-envelope-to'] = msg['Envelope-to']
	
	del fwd_msg['Envelope-to']
	fwd_msg['Envelope-to'] = to

	return fwd_msg

def connect_service( name, dry = False, passwords = None, **acc ):
	protocol = acc['protocol']
	
	if 'user' in acc:
		n = acc['user'] + '@' + acc['host']
		
		if name in passwords:
			acc['password'] = passwords[name]
		elif n in passwords:
			acc['password'] = passwords[n]
		elif not 'password' in acc:
			raise Exception("no password found for %s" % name)
	
	if protocol in ("pop", "pop3"):
		serv = Pop3Service( **acc )
	elif protocol in ("imap", "imap4"):
		serv = Imap4Service( **acc )
	elif protocol in ("smtp",):
		serv = SmtpService( **acc )
	else:
		raise Exception("unknown protocol: %s" % protocol)
		
	serv.dry = dry
	serv.open()
	
	return serv
	
def connect_services( accounts, dry = False, passwords = None ):
	services = {}
	
	for name, acc in accounts.items():
		serv = connect_service(name, dry = dry, passwords = passwords, **acc)
		services[name] = serv
		
		if acc['protocol'] == 'smtp' and not "smtp" in services:
			services["smtp"] = serv
		
	return services

def disconnect_services( services ):
	for serv in services.values():
		serv.close()

def load_config_script( cfgpath ):		
	cfg = imp.load_source("cfg", cfgpath)		
	return cfg
	
def run_script( scrpath ):		
	#XXX: use runpy.run_path instead? but we need the current __main__ as contex

	scr = imp.load_source("scr", scrpath)		
	return scr
	
password_line_pattern = re.compile('^\s*(.+)\s*[:=]\s*(.+?)\s*$')
	
def load_passwords( pwd_path ):
	f = open( pwd_path, 'ra' )
	
	passwords = {}
	for s in f:
		s = s.strip()
		if s == '': continue
		
		m = password_line_pattern.match( s )
		if m:
			acc = m.group(1)
			pwd = m.group(2)
			
			passwords[acc] = pwd
		
	f.close()
	return passwords
	
def run_filter_passes(services, passes, force_since = None, incremental = False, registry = None):
	for name, pass_ in passes.items():
		acc = pass_['account']
		srv = services[acc]
		
		filters = pass_["filters"]
		
		since = pass_.get("since")
		max_messages = pass_.get("max_messages")
		mailbox = pass_.get("mailbox")
		
		if force_since:
			since = force_since
		
		log("RUNNING PASS %s ON %s" % (name, acc))
			
		if not mailbox:
			mailbox = "INBOX"
			
		if incremental and registry is not None:
			if not name in registry:
				registry[name] = {}
			persist = registry[name]
		else:
			persist = None
		
		srv.process_messages(filters = filters, 
							 since = since, 
							 max_messages = max_messages, 
							 mailbox = mailbox,
							 persist = persist)

# --------------------------------------------------------------------------------------------
debug = False
quiet = False

accounts = {}
passes = {}
default_actions = []
registry_file = None
password_file = os.getcwd() + "/mailmux.pwd"
force_since = None

if __name__ == '__main__': 
	parser = argparse.ArgumentParser(description='Automatic mail filtering and forwarding')

#	parser.add_argument('integers', metavar='N', type=int, nargs='+',
#					   help='an integer for the accumulator')

	parser.add_argument('-v', '--verbose', '--debug', dest='debug', action='store_const',
						const=True, default=False,
						help="Enable debug output")

	parser.add_argument('-q', '--quiet', dest='quiet', action='store_const',
						const=True, default=False,
						help="Disable all output except errors")

	parser.add_argument('-c', '--config', dest='config_file', action='store',
					   default=os.getcwd() + "/mailmux.cfg.py", nargs='?', metavar='F',
					   help='Path to configuration script')

	parser.add_argument('--script', dest='script_file', action='store',
					   default=None, nargs='?', metavar='F',
					   help='Run script F and exit')

	parser.add_argument('--mailboxes', dest='mailboxes_for', action='store',
					   default=None, nargs='?', metavar='A',
					   help='List mailboxes in account A. A must be an account name as given in the config script (see --accounts)')

	parser.add_argument('--accounts', dest='list_accounts', action='store_const',
						const=True, default=False,
					   help='List all accounts in the configuration file')

	parser.add_argument('-p', '--passwd-file', dest='passwd_file', action='store',
					   default=None, nargs='?', metavar='F',
					   help='Path to password file')

	parser.add_argument('-s', '--since', dest='since', action='store',
					   default=None, nargs='?', metavar='D',
					   help='Process only messages since date D (format: yyyy-mm-dd hh:mm:dd)')

	parser.add_argument('-i', '--incremental', dest='incremental', action='store_const',
						const=True, default=False,
						help="Enable incremental processing")

	parser.add_argument('-t', '--test', '--dry', dest='dry', action='store_const',
						const=True, default=False,
						help="Dry mode, do not apply actions")

	args = parser.parse_args()
	
	debug = args.debug
	quiet = args.quiet

	force_since = args.since

	trace("LOADING CONFIG FROM %s" % args.config_file)
	cfg = load_config_script(args.config_file)		

	accounts = cfg.accounts
	passes = cfg.passes
	default_actions = cfg.default_actions
	registry_file = cfg.registry_file
	
	if cfg.password_file:
		password_file = cfg.password_file
	
	if password_file:
		trace("LOADING PASSWORDS FROM %s " % password_file)
		passwords = load_passwords( password_file )
	else:
		passwords = None

	if args.list_accounts:
		for name, acc in accounts.items():
			print "%s: " % (name, )
			print "    %s:%s, user %s" % (acc['protocol'], acc['host'], acc['user'])

	elif args.mailboxes_for:
		name = args.mailboxes_for
		print name
		serv = connect_service(name, dry = args.dry, passwords = passwords, **accounts[name])
		
		mailboxes = serv.list_mailboxes()
		for m in mailboxes:
			print m
		
		serv.close()

	else:
			
		if registry_file:
			trace("LOADING STATE FROM %s " % registry_file)
			
			if os.path.exists( registry_file ):
				#try:
					f = open(registry_file, "rb")
					registry = pickle.load( f )
					f.close();
				#except Exception, e:
				#	complain("ERROR: failed to load persistent registry from %s: %s" % (registry_file, e) )
				#	registry = {}
			else:
				registry = {}
		else:
			registry = None
			
		log("CONNECTING TO %i ACCOUNTS" % len(accounts))
		services = connect_services(accounts, dry = args.dry, passwords = passwords)
		#pprint.pprint(services)

		if args.script_file:
			log("RUNNING SCRIPT %s" % args.script_file)
			run_script(args.script_file)
		else:
			run_filter_passes( services, passes, force_since = force_since, incremental = args.incremental, registry = registry )

		trace("DISCONNECTING FROM %i SERVICES" % len(services))
		disconnect_services(services)
		
		if registry_file and registry:
			trace("PERSISTING STATE TO %s " % registry_file)

			f = open(registry_file, "wb")
			pickle.dump( registry, f )
			f.close()

	trace("DONE.")
