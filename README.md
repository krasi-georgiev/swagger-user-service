rm -Rf /tmp/app.rsa*
openssl genrsa -out /tmp/app.rsa
openssl rsa -in /tmp/app.rsa -pubout > /tmp/app.rsa.pub


/v1
	/user
			/login
			/create
			/pass , reset , update(PATCH)

JWT scopes

TODO:
	user registration

	implement context cancelling
	testing
