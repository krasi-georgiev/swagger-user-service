rm -Rf /tmp/app.rsa*
openssl genrsa -out /tmp/app.rsa
openssl rsa -in /tmp/app.rsa -pubout > /tmp/app.rsa.pub


TODO:

	/user delete

	/user/password
		reset - send an email
		change - enter the old one, new one  and if matched change


	implement context cancelling
	testing ???
