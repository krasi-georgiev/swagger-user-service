// Code generated by go-swagger; DO NOT EDIT.

package restapi

import (
	"crypto/rsa"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"net/mail"

	"github.com/dgrijalva/jwt-go"
	errors "github.com/go-openapi/errors"
	runtime "github.com/go-openapi/runtime"
	middleware "github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/rs/cors"
	graceful "github.com/tylerb/graceful"
	"golang.org/x/crypto/bcrypt"

	"github.com/choicehealth/user-service/models"
	"github.com/choicehealth/user-service/restapi/operations"
	"github.com/choicehealth/user-service/restapi/operations/users"

	"database/sql"

	_ "github.com/lib/pq"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
	db        *sql.DB
	userScope []string
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

	// Applies when the "x-token" header is set
	// parse the token
	api.SwtAuthAuth = func(token string) (interface{}, error) {
		t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})

		switch err.(type) {

		case nil:
			if !t.Valid { // but may still be invalid
				return nil, errors.New(401, "invalid swt token")
			}

		case *jwt.ValidationError: // something was wrong during the validation
			vErr := err.(*jwt.ValidationError)

			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				return errors.New(440, "token expired, login again"), nil
			default:
				return errors.New(500, "system error"), nil
			}
		default: // something else went wrong
			return errors.New(500, "system error"), nil
		}

		c := t.Claims.(jwt.MapClaims)

		userScope = strings.Split(c["scope"].(string), ",")

		return t, nil
	}

	api.UsersPostCreateHandler = users.PostCreateHandlerFunc(func(params users.PostCreateParams, principal interface{}) middleware.Responder {
		_, ok := principal.(*jwt.Token)
		if !ok {
			return users.NewPostCreateDefault(0)
		}

		// check if can create users
		for _, v := range userScope {
			if v == "create" {
				rows, err := db.Query("SELECT id FROM public.user WHERE username=$1", params.Body.Email)
				if err != nil {
					log.Println(err)
					return users.NewPostLoginDefault(0)
				}
				defer rows.Close()

				for rows.Next() {
					return users.NewPostCreateConflict().WithPayload(&models.Response{Code: swag.String("409"), Message: swag.String("user already exists")})
				}
				e, err := mail.ParseAddress(*params.Body.Email)
				if err != nil {
					return users.NewPostCreateConflict().WithPayload(&models.Response{Code: swag.String("409"), Message: swag.String("invalid email")})
				}

				var id int
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.Pass), bcrypt.DefaultCost)
				if err != nil {
					users.NewPostCreateDefault(0)
					log.Println(err)
				}
				err = db.QueryRow("INSERT INTO public.user (username, password,user_type_id,tenant_id)	VALUES ($1, $2, $3, $4)	RETURNING id", e.Address, hashedPassword, 1, 1).Scan(&id)
				if err != nil {
					users.NewPostCreateDefault(0)
					log.Println(err)
				}
				return users.NewPostCreateOK().WithPayload(users.PostCreateOKBody{IDProfile: swag.String(strconv.Itoa(id))})
			}
		}
		return users.NewPostCreateUnauthorized().WithPayload(&models.Response{Code: swag.String("401"), Message: swag.String("don't have user creation scope")})

	})

	api.UsersPostLoginHandler = users.PostLoginHandlerFunc(func(params users.PostLoginParams) middleware.Responder {
		rows, err := db.Query("SELECT id,user_type_id,password FROM public.user WHERE username=$1", params.Body.Email)
		if err != nil {
			log.Println(err)
			return users.NewPostLoginDefault(0)
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var user_type_id int
			var password string
			rows.Scan(&id, &user_type_id, &password)
			if bcrypt.CompareHashAndPassword([]byte(password), []byte(*params.Body.Pass)) == nil {
				t := jwt.MapClaims{
					"exp":   time.Now().Add(time.Hour * 72).Unix(),
					"scope": "browse",
				}
				switch user_type_id {
				case 1: //admin
					t["scope"] = t["scope"].(string) + ",create"
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
				tt, err := token.SignedString(signKey)
				if err != nil {
					return users.NewPostLoginDefault(0)
				}
				return users.NewPostLoginOK().WithPayload(users.PostLoginOKBody{Token: swag.String(tt)})
			}
		}
		return users.NewPostLoginNotFound()
	})

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
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			log.Fatalf("error parsing the  private key :%v", err)
		}
	}
	if key, err := ioutil.ReadFile(keysPaths.Pub); err != nil {
		log.Fatalf("can't read private file:%v", err)

	} else {
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(key)
		if err != nil {
			log.Fatalf("error parsing the  public key :%v", err)
		}
	}

	if d, err := sql.Open("postgres", "postgres://"+os.Getenv("DB_USER")+":"+os.Getenv("DB_PASS")+"@"+os.Getenv("DB_HOST")+"/choicehealth?sslmode=disable"); err != nil {
		log.Fatalf("error connecting to the DB :%v", err)
	} else {
		db = d
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
		AllowedMethods: []string{},
		MaxAge:         1000,
	})
	return corsHandler.Handler(handler)
}
