[Preview the Swagger Spec](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/choicehealth/user-service/master/swagger.yaml)

rm -Rf /tmp/app.rsa*
openssl genrsa -out /tmp/app.rsa
openssl rsa -in /tmp/app.rsa -pubout > /tmp/app.rsa.pub


TODO:

/user/password

set reset password on next login


	/user/management (PUT) - update an account
		creating an user - add to roles tables when user created

	implement baning based on ip
	ability to set and change roles


	implement context cancelling
	testing ???
