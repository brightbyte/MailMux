from __main__ import *

registry_file = "/path/to/your/mailmux.reg"
password_file = "/path/to/your/mailmux.pwd"
stdout_encoding = "utf-8"

accounts = {
	"imap:gmail" : {
		"protocol": "imap",
		"security": "ssl",
		"auth": None,
		"host": "imap.googlemail.com",
		"user": "yours.truly@gmail.com",
		"timeout": None,
	},
	
	"imap:acme" : {
		"protocol": "imap",
		"security": "ssl",
		"auth": None,
		"host": "mail.acme.com",
		"user": "frank@acme.com",
		"timeout": None,
	},

	"smtp:acme" : {
		"protocol": "smtp",
		"security": "ssl",
		"host": "mail.acme.com",
		"user": "frank@acme.com",
		"timeout": None,
	}
}

common_filters = [
	#none
]

default_actions = ABORT

passes = {
	
	"gmail" : {
		"account": "imap:gmail",
		"max_messages": 100,
		"since": None,
		"mailbox": "INBOX",
		"filters": [
			# copy everything to private inbox on acme.com
			( Yes(), ( Transfer("imap:acme.com", "INBOX"), abort_action ) ),
		]
	},
		
	"acme" : {
		"account": "imap:acme",
		"max_messages": 100,
		"since": None,
		"mailbox": "INBOX",
		"filters": common_filters + [
			# mark my own stuff as read
			( Contains("From", "@acme.com"), ( Tag('NonJunk'), seen_action, abort_action ) ),

			# move spam  
			( Matches("X-Spam-Level", r"^Yes,"), ( Tag('Junk'), Move("INBOX.Junk"), seen_action, abort_action ) ),
			
			# move boring stuff to News
			( Contains("From", ['forum@linuxquestions.org', 
								'news@linkedin.com',
								'group-digests@linkedin.com'] ), ( Move("INBOX.News"), seen_action, abort_action ) ),

			# skip notifications, but keep in inbox
			( Contains("From", ['@postmaster.twitter.com',
								'@facebook.com',] ), ( abort_action, ) ),
			
			# delete some junk
			( And( Contains("From", ['@evil.org', '@silly.com', ] ),
				   Contains("To", 'info@acme.com' ) ), ( delete_action, abort_action ) ),
			
			# default: do nothing
			( Yes(), abort_action ) 
		],
	},
	
}
