rm -Rf /tmp/app.rsa*
openssl genrsa -out /tmp/app.rsa
openssl rsa -in /tmp/app.rsa -pubout > /tmp/app.rsa.pub


TODO:
	2fa - put to enable on the account
	2fa - delete to disable 2fa on account - need to provide an existing password to disable

	/user delete

	/user/password
		reset - send an email
		change - enter the old one, new one  and if matched change


	implement context cancelling
	testing ???
