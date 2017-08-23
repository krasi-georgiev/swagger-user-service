[Preview the Swagger Spec](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/choicehealth/user-service/master/swagger.yaml)

rm -Rf /tmp/app.rsa*
openssl genrsa -out /tmp/app.rsa
openssl rsa -in /tmp/app.rsa -pubout > /tmp/app.rsa.pub


TODO:

	/user list all users
	/user/management (PUT) - update an account
	/user/password
	/user/roles to list all roles ?? do we need that ?
	/failedlogins ?? need more info on usage
	/sessions/  ?? need more info on usage
		reset - send an email
		change - enter the old one, new one  and if matched change


	implement context cancelling
	testing ???
