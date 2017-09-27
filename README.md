### REST Api based on go-swagger - returns json data for front end use.

autnentication is jwt token based with optional  2 factor google authenticator<br/>
postgresql as a storage backend<br/>
## [Live Preview](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/krasi-georgiev/swagger-user-service/master/swagger.yaml)


Generate pub/priv key for the jwt token generating and validaitng
```
rm -Rf /root/.ssh/user-service.rsa*
openssl genrsa -out /root/.ssh/user-service.rsa
openssl rsa -in /root/.ssh/user-service.rsa -pubout > /root/.ssh/user-service.rsa.pub
```

Install the go-swagger generator
<br/>`go get -u github.com/go-swagger/go-swagger/cmd/swagger`

Generate
<br/>`swagger generate server ./swagger.yaml`

Start
<br/>`DB_HOST=0.0.0.0 DB_PASS=pass DB_USER=user go run cmd/user-management-server --port=80 --host=0.0.0.0 --pub=/root/.ssh/user-service.rsa.pub --priv=/root/.ssh/user-service.rsa`


TODO:
- [ ] throttle ip
- [ ] setup proper role based permissions
- [ ] testing
