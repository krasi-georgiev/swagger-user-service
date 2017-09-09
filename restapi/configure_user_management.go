package restapi

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	errors "github.com/go-openapi/errors"
	runtime "github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/rs/cors"
	graceful "github.com/tylerb/graceful"

	"github.com/vanderbr/choicehealth_user-service/handlers"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"

	_ "github.com/lib/pq"
)

// This file is safe to edit. Once it exists it will not be overwritten

//go:generate swagger generate server --target .. --name  --spec ../swagger.yaml
var keysPaths = struct {
	Pub  string `long:"pub" description:"public key path for the swt token generation" default:"/tmp/app.rsa.pub"`
	Priv string `long:"priv" description:"private key path for the swt token verification" default:"/tmp/app.rsa"`
}{}

func configureFlags(api *operations.UserManagementAPI) {
	api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{
		swag.CommandLineOptionsGroup{
			ShortDescription: "private pub key paths",
			Options:          &keysPaths,
		},
	}

}

func configureAPI(api *operations.UserManagementAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	// Applies when the "x-jwt" header is set
	// parse the token
	api.JwtAuth = func(token string) (interface{}, error) {
		t, err := handlers.ParseJwt(token)
		if err != nil {
			return nil, errors.New(401, "authentication failed")
		}

		if t.F2a {
			return nil, errors.New(401, "account is with 2 factor enabled so hit the 2 factor endpoint first")
		}
		if t.RequirePassReset {
			return nil, errors.New(401, "account requires a password change so hit the pass reset endpoint using the provided  temporary password")
		}

		return t, nil
	}

	api.GetUsersHandler = operations.GetUsersHandlerFunc(handlers.UserList)

	api.PostUserHandler = operations.PostUserHandlerFunc(handlers.UserCreate)

	api.PutUserIDHandler = operations.PutUserIDHandlerFunc(handlers.UserUpdate)

	api.DeleteUserIDHandler = operations.DeleteUserIDHandlerFunc(handlers.UserDelete)

	api.PostUserLoginHandler = operations.PostUserLoginHandlerFunc(handlers.UserLogin)

	api.PutUserLoginHandler = operations.PutUserLoginHandlerFunc(handlers.ParseToken)

	api.PostUserIDPasswordHandler = operations.PostUserIDPasswordHandlerFunc(handlers.PassReset)

	api.PutUserIDPasswordHandler = operations.PutUserIDPasswordHandlerFunc(handlers.PassResetTemp)

	api.DeleteUserIDF2aHandler = operations.DeleteUserIDF2aHandlerFunc(handlers.F2aDisable)

	api.GetUserF2aHandler = operations.GetUserF2aHandlerFunc(handlers.F2aGenerator)

	api.PutUserIDF2aHandler = operations.PutUserIDF2aHandlerFunc(handlers.F2aEnable)

	api.PostUserF2aHandler = operations.PostUserF2aHandlerFunc(handlers.F2aAuthenticate)

	api.DeleteUserRoleIDHandler = operations.DeleteUserRoleIDHandlerFunc(handlers.RoleDelete)

	api.GetUserRolesHandler = operations.GetUserRolesHandlerFunc(handlers.Roles)

	api.PostUserRoleHandler = operations.PostUserRoleHandlerFunc(handlers.RoleCreate)

	api.PutUserRoleIDHandler = operations.PutUserRoleIDHandlerFunc(handlers.RoleUpdate)

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *graceful.Server, scheme, addr string) {

	if key, err := ioutil.ReadFile(keysPaths.Priv); err != nil {
		log.Fatalf("can't read public file:%v", err)
	} else {
		handlers.SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			log.Fatalf("error parsing the  private key :%v", err)
		}
	}
	if key, err := ioutil.ReadFile(keysPaths.Pub); err != nil {
		log.Fatalf("can't read private file:%v", err)

	} else {
		handlers.VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(key)
		if err != nil {
			log.Fatalf("error parsing the  public key :%v", err)
		}
	}
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	corsHandler := cors.New(cors.Options{
		Debug:          false,
		AllowedHeaders: []string{"*"},
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"},
		MaxAge:         1000,
	})
	return corsHandler.Handler(handler)
}
