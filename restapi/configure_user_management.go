package restapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"image/png"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	qr "github.com/qpliu/qrencode-go/qrencode"

	"net/mail"

	"encoding/base32"

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

	"database/sql"

	_ "github.com/lib/pq"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
	db        *sql.DB
	f2a       bool
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
		t, err := ParseJwt(token)
		if err != nil {
			return nil, err
		}

		if t.F2a {
			return nil, errors.New(401, "account is with 2 factor enabled so hit the 2 factor endpoint first")
		}

		return t, nil
	}

	api.PostUserManagementHandler = operations.PostUserManagementHandlerFunc(func(params operations.PostUserManagementParams, principal interface{}) middleware.Responder {

		// check if can create users
		for _, v := range principal.(*Jwt).Scope {
			if v == "create" {
				rows, err := db.Query("SELECT id FROM public.user WHERE username=$1", params.Body.Email)
				if err != nil {
					log.Println(err)
					return operations.NewPostUserManagementDefault(0)
				}
				defer rows.Close()

				for rows.Next() {
					return operations.NewPostUserManagementConflict().WithPayload(&models.Response{Code: swag.String("409"), Message: swag.String("user already exists")})
				}
				e, err := mail.ParseAddress(*params.Body.Email)
				if err != nil {
					return operations.NewPostUserManagementConflict().WithPayload(&models.Response{Code: swag.String("409"), Message: swag.String("invalid email")})
				}

				var id int
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.Password), bcrypt.DefaultCost)
				if err != nil {
					operations.NewPostUserManagementDefault(0)
					log.Println(err)
				}

				role, err := strconv.Atoi(*params.Body.UserTypeID)
				if err != nil {
					operations.NewPostUserManagementDefault(0)
					log.Println(err)
				}

				tenant, err := strconv.Atoi(*params.Body.TenantID)
				if err != nil {
					operations.NewPostUserManagementDefault(0)
					log.Println(err)
				}
				err = db.QueryRow("INSERT INTO public.user (username, password,user_type_id,tenant_id)	VALUES ($1, $2, $3, $4)	RETURNING id", e.Address, hashedPassword, role, tenant).Scan(&id)
				if err != nil {
					operations.NewPostUserManagementDefault(0)
					log.Println(err)
				}
				return operations.NewPostUserManagementOK().WithPayload(operations.PostUserManagementOKBody{IDProfile: swag.String(strconv.Itoa(id))})
			}
		}
		return operations.NewPostUserManagementUnauthorized().WithPayload(&models.Response{Code: swag.String("401"), Message: swag.String("don't have user creation scope")})

	})

	api.PostUserLoginHandler = operations.PostUserLoginHandlerFunc(func(params operations.PostUserLoginParams) middleware.Responder {
		rows, err := db.Query("SELECT id,user_type_id,password,f2a FROM public.user WHERE username=$1", params.Body.Email)

		if err != nil {
			log.Println(err)
			return operations.NewPostUserLoginDefault(0)
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var user_type_id int
			var password string
			var f2a string

			rows.Scan(&id, &user_type_id, &password, &f2a)

			if bcrypt.CompareHashAndPassword([]byte(password), []byte(*params.Body.Password)) == nil {
				t := jwt.MapClaims{
					"exp":          time.Now().Add(time.Hour * 240).Unix(),
					"id_profile":   strconv.Itoa(id),
					"user_type_id": strconv.Itoa(user_type_id),
				}
				t["scope"] = SetScopes(user_type_id)

				if f2a != "" { // user has f2a enabled so need an extra token verificaiton using the f2a endpoint
					t["f2a"] = "enabled"
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
				tt, err := token.SignedString(signKey)
				if err != nil {
					return operations.NewPostUserLoginDefault(0)
				}
				return operations.NewPostUserLoginOK().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
			}
		}
		return operations.NewPostUserLoginNotFound()
	})

	api.DeleteUser2faHandler = operations.DeleteUser2faHandlerFunc(func(params operations.DeleteUser2faParams, principal interface{}) middleware.Responder {
		return middleware.NotImplemented("operation .DeleteUser2fa has not yet been implemented")
	})

	// qr and salt generator
	api.GetUser2faHandler = operations.GetUser2faHandlerFunc(func(params operations.GetUser2faParams, principal interface{}) middleware.Responder {
		buf := bytes.Buffer{}
		err := binary.Write(&buf, binary.BigEndian, int64(math.Floor(float64(time.Now().UnixNano())/float64(1000)/float64(30))))
		if err != nil {
			log.Println(err)
			return operations.NewGetUser2faDefault(0)

		}
		h := hmac.New(func() hash.Hash { return sha256.New() }, buf.Bytes())
		s := string(h.Sum(nil))

		if qr, err := BarcodeImage("Choicehealth", []byte(s)); err == nil {
			return operations.NewGetUser2faOK().WithPayload(operations.GetUser2faOKBody{Qr: swag.String(qr), Secret: swag.String(fmt.Sprintf("%x", s))})

		} else {
			log.Println(err)
			return operations.NewGetUser2faDefault(0)

		}
	})
	api.PutUser2faHandler = operations.PutUser2faHandlerFunc(func(params operations.PutUser2faParams, principal interface{}) middleware.Responder {
		return middleware.NotImplemented("operation .PostUser2fa has not yet been implemented")
	})

	// authenticate against the 2fa
	api.PostUser2faHandler = operations.PostUser2faHandlerFunc(func(params operations.PostUser2faParams) middleware.Responder {
		var tt *Jwt
		if t, err := ParseJwt(*params.Body.Jwt); err != nil {
			log.Println(err)
			return operations.NewPostUser2faUnauthorized().WithPayload(&models.Response{Code: swag.String(strconv.Itoa(int(err.Code()))), Message: swag.String(err.Error())})
		} else {
			tt = t
		}

		var f2a string
		err := db.QueryRow("SELECT f2a FROM public.user WHERE id=$1", tt.Id_profile).Scan(&f2a)
		if err != nil {
			log.Println(err)
			return operations.NewPutUser2faDefault(0)
		}

		code, _, err := GetCurrent2faCode(f2a)
		if err != nil {
			log.Println(err)
			return operations.NewPutUser2faDefault(0)
		}

		if strconv.Itoa(code) == *params.Body.F2a {

			// now generate a new jwt token without the 2fa lock
			t := jwt.MapClaims{
				"exp":          time.Now().Add(time.Hour * 240).Unix(),
				"id_profile":   strconv.Itoa(tt.Id_profile),
				"user_type_id": strconv.Itoa(tt.User_type_id),
			}
			t["scope"] = SetScopes(tt.User_type_id)

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
			tt, err := token.SignedString(signKey)
			if err != nil {
				return operations.NewPutUser2faDefault(0)
			}
			return operations.NewPostUser2faOK().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
		}
		return operations.NewPostUser2faUnauthorized().WithPayload(&models.Response{Code: swag.String("401"), Message: swag.String("invalid 2fa token")})

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
		AllowedMethods: []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"},
		MaxAge:         1000,
	})
	return corsHandler.Handler(handler)
}

func BarcodeImage(label string, secretkey []byte) (string, error) {
	issuer := "go-google-authenticator"

	otp_str := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, "Choicehealth", base32.StdEncoding.EncodeToString(secretkey), issuer)

	c, err := qr.Encode(otp_str, qr.ECLevelM)

	if err != nil {
		return "", err
	}

	var buf bytes.Buffer

	err = png.Encode(&buf, c.Image(8))

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func GetCurrent2faCode(secretKey string) (int, int64, error) {
	now := time.Now().Unix()
	interval := 30
	t_chunk := (now / int64(interval))

	buf_in := bytes.Buffer{}
	err := binary.Write(&buf_in, binary.BigEndian, int64(t_chunk))
	if err != nil {
		return 0, 0, err
	}

	h := hmac.New(func() hash.Hash { return sha1.New() }, bytes.NewBufferString(secretKey).Bytes())
	h.Reset()

	h.Write(buf_in.Bytes())
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xF
	code_sect := sum[offset : offset+4]

	var code int32
	buf_out := bytes.NewBuffer(code_sect)
	err = binary.Read(buf_out, binary.BigEndian, &code)
	if err != nil {
		return 0, 0, err
	}

	code = code & 0x7FFFFFFF

	code = code % 1000000

	i := int64(interval)
	x := (((now + i) / i) * i) - now

	return int(code), x, nil
}

func SetScopes(user_type_id int) string {
	scope := "browse"
	switch user_type_id {
	case 1: //admin
		scope = scope + ",create"
	}
	return scope
}

func ParseJwt(token string) (*Jwt, errors.Error) {
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
			return nil, errors.New(440, "token expired, login again")
		default:
			return nil, errors.New(500, "system error")
		}
	default: // something else went wrong
		return nil, errors.New(500, "system error")
	}

	j := &Jwt{}

	if id_profile, err := strconv.Atoi(t.Claims.(jwt.MapClaims)["id_profile"].(string)); err == nil {
		j.Id_profile = id_profile
	} else {
		log.Println("parsing user id error:", err)
		return nil, errors.New(500, "system error")
	}
	if user_type_id, err := strconv.Atoi(t.Claims.(jwt.MapClaims)["user_type_id"].(string)); err == nil {
		j.User_type_id = user_type_id
	} else {
		log.Println("parsing user type error:", err)
		return nil, errors.New(500, "system error")
	}
	if scope, ok := t.Claims.(jwt.MapClaims)["scope"].(string); ok {
		j.Scope = strings.Split(scope, ",")
	} else {
		log.Println("parsing user scopes error:", err)
		return nil, errors.New(500, "system error")
	}
	if s, ok := t.Claims.(jwt.MapClaims)["f2a"].(string); ok && s != "" {
		j.F2a = true
	}

	return j, nil
}

type Jwt struct {
	Id_profile, User_type_id int
	F2a                      bool
	Scope                    []string
}
