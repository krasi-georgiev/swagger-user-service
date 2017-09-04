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
	"encoding/json"
	"fmt"
	"hash"
	"image/png"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
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

	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"

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
		if t.RequirePassReset {
			return nil, errors.New(401, "account requires a password change so hit the pass reset endpoint using the provided  temporary password")
		}

		return t, nil
	}

	api.GetUserHandler = operations.GetUserHandlerFunc(func(params operations.GetUserParams, principal interface{}) middleware.Responder {
		var (
			f2a, id, voice    int64
			username, created sql.NullString
		)

		var limit string
		if params.Limit != nil {
			limit = " LIMIT " + strconv.Itoa(int(*params.Limit))
		}
		var offset string
		if params.Offset != nil {
			offset = " OFFSET " + strconv.Itoa(int(*params.Offset))
		}

		var voiceFilter string
		if *params.Voice == true {
			voiceFilter = " WHERE  voice is TRUE"
		}

		rows, err := db.Query("select id, username,created,CASE WHEN voice IS false THEN -1 ELSE 1 end as voice,CASE WHEN f2a IS NULL THEN -1 ELSE 1 end as f2a from public.user" + voiceFilter + limit + offset + ";")
		if err != nil {
			log.Println(err)
			return operations.NewGetUserDefault(0)
		}
		var users []*operations.GetUserOKBodyItems0
		for rows.Next() {
			if err := rows.Scan(&id, &username, &created, &voice, &f2a); err != nil {
				log.Println(err)
				return operations.NewGetUserDefault(0)
			}
			users = append(users, &operations.GetUserOKBodyItems0{Created: created.String, Voice: voice, F2a: f2a, ID: id, Username: username.String})

		}
		return operations.NewGetUserOK().WithPayload(users)
	})

	api.PostUserManagementHandler = operations.PostUserManagementHandlerFunc(func(params operations.PostUserManagementParams, principal interface{}) middleware.Responder {

		// _, ok := principal.(*Jwt)
		// if !ok {
		// 	return operations.NewPostUserManagementDefault(0)
		// }
		// check if can create users
		// if !CheckScope(j.Scope, "createUser") {
		// 	return operations.NewPostUserManagementUnauthorized().WithPayload(&models.Response{Code: swag.String("401"), Message: swag.String("don't have user creation scope")})
		// }
		rows, err := db.Query("SELECT id FROM public.user WHERE username=$1", params.Body.Username)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserManagementDefault(0)
		}
		defer rows.Close()

		for rows.Next() {
			return operations.NewPostUserManagementConflict().WithPayload(&models.Response{Code: swag.Int64(409), Message: swag.String("user already exists")})
		}

		email := ""
		if params.Body.Email != "" {
			e, err := mail.ParseAddress(params.Body.Email)
			if err != nil {
				return operations.NewPostUserManagementConflict().WithPayload(&models.Response{Code: swag.Int64(409), Message: swag.String("invalid email")})
			}
			email = e.Address
		}

		var id int64
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserManagementDefault(0)

		}

		// check if all values in the role array include valid roles
		roleV := ""
		for _, v := range params.Body.Role {
			roleV = roleV + strconv.Itoa(int(v)) + ","
		}
		// remove the last comma
		roleV = roleV[:len(roleV)-1]

		result, err := db.Exec("SELECT id FROM role WHERE id IN (" + roleV + ") ;")
		if err != nil {
			log.Println(err)
			return operations.NewPostUserManagementDefault(0)
		}
		if count, err := result.RowsAffected(); err != nil || count < int64(len(params.Body.Role)) {
			return operations.NewPostUserManagementDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("role array includes invalid id")}))
		}

		roles := ""
		for _, v := range params.Body.Role {
			roles = roles + "((SELECT id FROM profileInsert), " + strconv.Itoa(int(v)) + "),"
		}
		// remove the last comma
		roles = roles[:len(roles)-1]
		query := `
		WITH profileInsert as (
			INSERT INTO public.user (username,email,active,voice password,tenant_id,created,reset_password_next_login,person_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)	RETURNING id),
			insertProfileRole as (
				INSERT INTO user_role (user_id,role_id)
				VALUES ` + roles + `
				)
			SELECT * FROM profileInsert`

		err = db.QueryRow(query, *params.Body.Username, email, params.Body.Active, params.Body.Voice, hashedPassword, params.Body.TenantID, time.Now(), params.Body.ResetPasswordNextLogin, params.Body.PersonID).Scan(&id)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserManagementDefault(0)
		}
		return operations.NewPostUserManagementOK().WithPayload(operations.PostUserManagementOKBody{IDProfile: &id})

	})
	api.PutUserManagementHandler = operations.PutUserManagementHandlerFunc(func(params operations.PutUserManagementParams, principal interface{}) middleware.Responder {

		tx, err := db.Begin()
		if err != nil {
			log.Println(err)
			return operations.NewPutUserManagementDefault(0)
		}

		if params.Body.Password != "" {
			var hashedPassword []byte
			hashedPassword, err = bcrypt.GenerateFromPassword([]byte(params.Body.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Println(err)
				return operations.NewPutUserManagementDefault(0)
			}
			_, err = tx.Exec("UPDATE public.user SET password=$1  WHERE id=$2;", hashedPassword, params.Body.ID)

		}

		if params.Body.Active != "" {
			var active bool
			switch params.Body.Active {
			case "true":
				active = true
			default:
				active = false
			}
			_, err = tx.Exec("UPDATE public.user SET active=$1  WHERE id=$2;", active, params.Body.ID)

		}

		if params.Body.Voice != "" {
			var voice bool
			switch params.Body.Voice {
			case "true":
				voice = true
			default:
				voice = false
			}
			_, err = tx.Exec("UPDATE public.user SET voice=$1  WHERE id=$2;", voice, params.Body.ID)
		}

		if params.Body.Email != "" {
			_, err = tx.Exec("UPDATE public.user SET email=$1  WHERE id=$2;", params.Body.Email, params.Body.ID)
		}

		if params.Body.PersonID > 0 {
			_, err = tx.Exec("UPDATE public.user SET person_id=$1  WHERE id=$2;", params.Body.PersonID, params.Body.ID)
		}

		if params.Body.ResetPasswordNextLogin != "" {
			var reset bool
			switch params.Body.ResetPasswordNextLogin {
			case "true":
				reset = true
			default:
				reset = false
			}
			_, err = tx.Exec("UPDATE public.user SET reset_password_next_login=$1  WHERE id=$2;", reset, params.Body.ID)
		}

		if params.Body.TenantID > 0 {
			_, err = tx.Exec("UPDATE public.user SET tenant_id=$1  WHERE id=$2;", params.Body.TenantID, params.Body.ID)
		}

		if len(params.Body.Role) > 0 {
			_, err = tx.Exec("DELETE FROM user_role WHERE user_id=$1;", params.Body.ID)
			if err != nil {
				log.Println(err)
				return operations.NewPutUserManagementDefault(0)
			}

			// check if all values in the role array include valid roles
			roleV := ""
			for _, v := range params.Body.Role {
				roleV = roleV + strconv.Itoa(int(v)) + ","
			}
			// remove the last comma
			roleV = roleV[:len(roleV)-1]

			result, err := tx.Exec("SELECT id FROM role WHERE id IN (" + roleV + ") ;")
			if err != nil {
				log.Println(err)
				return operations.NewPutUserManagementDefault(0)
			}
			if count, err := result.RowsAffected(); err != nil || count < int64(len(params.Body.Role)) {
				return operations.NewPutUserManagementDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("role array includes invalid id")}))
			}

			roles := ""
			for _, v := range params.Body.Role {
				roles = roles + "(" + strconv.Itoa(int(*params.Body.ID)) + ", " + strconv.Itoa(int(v)) + "),"
			}
			// remove the last comma
			roles = roles[:len(roles)-1]
			_, err = tx.Exec("INSERT INTO user_role (user_id,role_id)	VALUES " + roles + ";")
		}

		if err != nil {
			log.Println(err)
			return operations.NewPutUserManagementDefault(0)
		}

		err = tx.Commit()
		if err != nil {
			tx.Rollback()
			log.Println(err)
			return operations.NewPutUserManagementDefault(0)
		}

		if params.Body.Username != "" {
			// before updating make sure the same username doesn't already exist
			rows, err := db.Query("SELECT id FROM public.user WHERE username=$1 AND id != $2", params.Body.Username, params.Body.ID)
			if err != nil {
				log.Println(err)
				return operations.NewPutUserManagementDefault(0)
			}
			defer rows.Close()

			for rows.Next() {
				return operations.NewPutUserManagementDefault(409).WithPayload(&models.Response{Code: swag.Int64(409), Message: swag.String("username  already exists")})
			}

			_, err = db.Exec("UPDATE public.user SET username=$1  WHERE id=$2;", params.Body.Username, params.Body.ID)
		}

		return operations.NewPutUserManagementOK()

	})
	api.DeleteUserManagementHandler = operations.DeleteUserManagementHandlerFunc(func(params operations.DeleteUserManagementParams, principal interface{}) middleware.Responder {

		if *params.Body.IDProfile < 1 {
			return operations.NewDeleteUserManagementDefault(400).WithPayload(&models.Response{Code: swag.Int64(400), Message: swag.String("invalid profile id")})
		}

		tx, err := db.Begin()
		if err != nil {
			log.Println(err)
			return operations.NewPostUserManagementDefault(0)
		}

		_, err = tx.Exec("DELETE FROM user_role WHERE user_id=$1;", *params.Body.IDProfile)
		if err != nil {
			log.Println(err)
			return operations.NewDeleteUserManagementDefault(0)
		}

		result, err := tx.Exec("DELETE FROM public.user WHERE id=$1 ;", *params.Body.IDProfile)
		if err != nil {
			log.Println(err)
			return operations.NewDeleteUserManagementDefault(0)
		}

		err = tx.Commit()
		if err != nil {
			log.Println(err)
			return operations.NewDeleteUserManagementDefault(0)
		}
		if count, err := result.RowsAffected(); err != nil || count == 0 {
			return operations.NewDeleteUserManagementDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("user with this id doesn't exist")}))
		}

		return operations.NewDeleteUserManagementOK()
	})

	api.PostUserLoginHandler = operations.PostUserLoginHandlerFunc(func(params operations.PostUserLoginParams) middleware.Responder {
		rows, err := db.Query("SELECT id,password,active,reset_password_next_login,f2a FROM public.user WHERE username=$1", params.Body.Username)

		if err != nil {
			log.Println(err)
			return operations.NewPostUserLoginDefault(0)
		}
		defer rows.Close()

		var id int
		var password string
		var active sql.NullBool
		var reset_password_next_login sql.NullBool
		var f2a sql.NullString

		for rows.Next() {

			if err := rows.Scan(&id, &password, &active, &reset_password_next_login, &f2a); err != nil {
				log.Println(err)
				return operations.NewPostUserLoginDefault(0)
			}

			if bcrypt.CompareHashAndPassword([]byte(password), []byte(*params.Body.Password)) == nil {
				t := jwt.MapClaims{
					"exp":        time.Now().Add(time.Hour * 240).Unix(),
					"id_profile": strconv.Itoa(id),
				}
				t["scope"], err = setScopes(id)
				if err != nil {
					log.Println(err)
					return operations.NewPostUserLoginDefault(0)
				}

				if !active.Bool {
					return operations.NewPostUserLoginDefault(401).WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("user is disabled")}))
				}

				if f2a.Valid { // user has f2a enabled so need an extra token verificaiton using the f2a endpoint
					t["f2a"] = true
				}
				if reset_password_next_login.Bool { // user has f2a enabled so need an extra token verificaiton using the f2a endpoint
					t["reset_password_next_login"] = true
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
				tt, err := token.SignedString(signKey)
				if err != nil {
					return operations.NewPostUserLoginDefault(0)
				}
				if f2a.Valid {
					return operations.NewPostUserLoginPartialContent().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
				}
				if reset_password_next_login.Bool {
					return operations.NewPostUserLoginCreated().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
				}
				return operations.NewPostUserLoginOK().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
			}
		}
		_, err = db.Exec("INSERT INTO public.failed_logins (timestamp,user_id,attempted_username) VALUES ($1,$2,$3) ;", time.Now(), id, params.Body.Username)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserLoginDefault(0)
		}
		return operations.NewPostUserLoginDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("invalid login")}))

	})

	api.PostUserPasswordHandler = operations.PostUserPasswordHandlerFunc(func(params operations.PostUserPasswordParams, principal interface{}) middleware.Responder {
		j, ok := principal.(*Jwt)
		if !ok {
			return operations.NewPostUserPasswordDefault(0)
		}

		// TODO check if the user is trying to change his own password or has permissions to check anyones password
		// prevents changing someone elses password
		if false && int64(j.Id_profile) != *params.Body.IDProfile {
			return operations.NewPostUserPasswordUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("no permission to change the password for this user")}))
		}

		allowed := false
		if false {
			var password string
			err := db.QueryRow("SELECT password FROM public.user WHERE id=$1", j.Id_profile).Scan(&password)
			if err != nil {
				log.Println(err)
				return operations.NewPostUserPasswordDefault(0)
			}
			if bcrypt.CompareHashAndPassword([]byte(password), []byte(params.Body.PasswordOld)) == nil {
				allowed = true
			} else {
				return operations.NewPostUserPasswordUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("old password doesn't match")}))
			}
		} else {
			allowed = true
		}
		if allowed {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.PasswordNew), bcrypt.DefaultCost)
			if err != nil {
				log.Println(err)

				return operations.NewPostUserPasswordDefault(0)
			}
			_, err = db.Exec("UPDATE public.user SET password=$1,reset_password_next_login=true WHERE id=$2 ;", hashedPassword, params.Body.IDProfile)
			if err != nil {
				log.Println(err)
				return operations.NewPostUserPasswordDefault(0)
			}
			return operations.NewPostUserPasswordOK()

		}
		return operations.NewPostUserPasswordUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("don't have permission to change this user password")}))

	})

	api.PutUserPasswordHandler = operations.PutUserPasswordHandlerFunc(func(params operations.PutUserPasswordParams) middleware.Responder {
		var tt *Jwt
		if t, err := ParseJwt(*params.Body.Jwt); err != nil {
			log.Println(err)
			return operations.NewPutUserPasswordUnauthorized().WithPayload(&models.Response{Code: swag.Int64(int64(err.Code())), Message: swag.String(err.Error())})
		} else {
			tt = t
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.PasswordNew), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserPasswordDefault(0)
		}

		_, err = db.Exec("UPDATE public.user SET password=$1,reset_password_next_login=false WHERE id=$2 ;", hashedPassword, tt.Id_profile)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserPasswordDefault(0)
		}
		return operations.NewPutUserPasswordOK()
	})

	api.DeleteUser2faHandler = operations.DeleteUser2faHandlerFunc(func(params operations.DeleteUser2faParams, principal interface{}) middleware.Responder {
		j, ok := principal.(*Jwt)
		if !ok {
			return operations.NewDeleteUser2faDefault(0)
		}

		var password string
		err := db.QueryRow("SELECT password FROM public.user WHERE id=$1", j.Id_profile).Scan(&password)

		if err != nil {
			log.Println(err)
			return operations.NewDeleteUser2faDefault(0)
		}
		// password ok so can disable 2fa
		if bcrypt.CompareHashAndPassword([]byte(password), []byte(*params.Body.Password)) == nil {
			_, err = db.Exec("UPDATE public.user SET f2a=NULL WHERE id=$1 ;", j.Id_profile)
			if err != nil {
				log.Println(err)
				return operations.NewDeleteUser2faDefault(0)
			}
			return operations.NewDeleteUser2faOK()

		}
		return operations.NewDeleteUser2faUnauthorized()

	})

	// qr and salt generator
	api.GetUser2faHandler = operations.GetUser2faHandlerFunc(func(params operations.GetUser2faParams, principal interface{}) middleware.Responder {
		secret, err := GenSecretKey()
		if err != nil {
			log.Println(err)
			return operations.NewGetUser2faDefault(0)
		}

		if qr, err := BarcodeImage("Choicehealth", []byte(secret)); err == nil {
			return operations.NewGetUser2faOK().WithPayload(operations.GetUser2faOKBody{Qr: swag.String(qr), Secret: swag.String(secret)})

		} else {
			log.Println(err)
			return operations.NewGetUser2faDefault(0)

		}
	})

	// Expects a valid 2fa token to verify and enable on the account
	api.PutUser2faHandler = operations.PutUser2faHandlerFunc(func(params operations.PutUser2faParams, principal interface{}) middleware.Responder {
		j, ok := principal.(*Jwt)
		if !ok {
			return operations.NewPutUser2faDefault(0)
		}
		// verify the code and if match save the master secret for the account
		code, _, err := GetCurrent2faCode(*params.Body.Secret)
		if err != nil {
			log.Println(err)
			return operations.NewPutUser2faDefault(0)
		}

		// code matches so can save the secret in the db
		if code == *params.Body.Code {
			_, err = db.Exec("UPDATE public.user SET f2a=$1 WHERE id=$2 ;", params.Body.Secret, j.Id_profile)
			if err != nil {
				log.Println(err)
				return operations.NewPutUser2faDefault(0)
			}
			return operations.NewPutUser2faOK()
		}
		return operations.NewPutUser2faUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("mismatched 2 factor code")}))

	})

	// authenticate against the 2fa
	api.PostUser2faHandler = operations.PostUser2faHandlerFunc(func(params operations.PostUser2faParams) middleware.Responder {
		var tt *Jwt
		if t, err := ParseJwt(*params.Body.Jwt); err != nil {
			log.Println(err)
			return operations.NewPostUser2faUnauthorized().WithPayload(&models.Response{Code: swag.Int64(int64(err.Code())), Message: swag.String(err.Error())})
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

		if code == *params.Body.F2a {

			// now generate a new jwt token without the 2fa lock
			t := jwt.MapClaims{
				"exp":        time.Now().Add(time.Hour * 240).Unix(),
				"id_profile": strconv.Itoa(tt.Id_profile),
				// "user_type_id": strconv.Itoa(tt.User_type_id),
			}
			t["scope"], err = setScopes(tt.Id_profile)
			if err != nil {
				return operations.NewPutUser2faDefault(0)
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
			tt, err := token.SignedString(signKey)
			if err != nil {
				return operations.NewPutUser2faDefault(0)
			}
			return operations.NewPostUser2faOK().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
		}
		return operations.NewPostUser2faUnauthorized().WithPayload(&models.Response{Code: swag.Int64(401), Message: swag.String("invalid 2fa token")})

	})

	api.DeleteUserRoleHandler = operations.DeleteUserRoleHandlerFunc(func(params operations.DeleteUserRoleParams, principal interface{}) middleware.Responder {
		r, err := db.Exec("DELETE FROM role WHERE id=$1 ;", params.Body.ID)
		if err != nil {
			log.Println(err)
			return operations.NewDeleteUserRoleDefault(0)
		}
		if count, err := r.RowsAffected(); err != nil || count == 0 {
			return operations.NewDeleteUserRoleDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("invalid role id")}))

		}
		return operations.NewDeleteUserRoleOK()
	})

	api.GetUserRoleHandler = operations.GetUserRoleHandlerFunc(func(params operations.GetUserRoleParams, principal interface{}) middleware.Responder {

		var limit string
		if params.Limit != nil {
			limit = " LIMIT " + strconv.Itoa(int(*params.Limit))
		}

		var offset string
		if params.Offset != nil {
			offset = " OFFSET " + strconv.Itoa(int(*params.Offset))
		}

		rows, err := db.Query("select id, name, data from role" + limit + offset + ";")
		if err != nil {
			log.Println(err)
			return operations.NewGetUserRoleDefault(0)
		}
		var roles []*models.UserRole
		for rows.Next() {
			var (
				id         int64
				name, data string
			)
			if err := rows.Scan(&id, &name, &data); err != nil {
				log.Println(err)
				return operations.NewGetUserRoleDefault(0)
			}
			roles = append(roles, &models.UserRole{ID: &id, Name: &name, Data: &data})
		}

		return operations.NewGetUserRoleOK().WithPayload(roles)
	})

	api.PostUserRoleHandler = operations.PostUserRoleHandlerFunc(func(params operations.PostUserRoleParams, principal interface{}) middleware.Responder {
		var id int64
		err := db.QueryRow("INSERT INTO role (name,data)	VALUES ($1)	RETURNING id", *params.Body.Name, *params.Body.Data).Scan(&id)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserRoleDefault(0)
		}
		return operations.NewPostUserRoleOK().WithPayload(operations.PostUserRoleOKBody{ID: &id})
	})

	api.PutUserRoleHandler = operations.PutUserRoleHandlerFunc(func(params operations.PutUserRoleParams, principal interface{}) middleware.Responder {
		result, err := db.Exec("UPDATE role SET name=$1,data=$2 WHERE id=$3 ;", params.Body.Name, params.Body.Data, params.Body.ID)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserRoleDefault(0)
		}
		if count, err := result.RowsAffected(); err != nil || count == 0 {
			return operations.NewPutUserRoleDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("role id not found")}))
		}
		return operations.NewPutUserRoleOK()
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
		issuer, label, base32.StdEncoding.EncodeToString(secretkey), issuer)

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

func GenSecretKey() (string, error) {

	hmac_hash := sha256.New()

	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, getTs())
	if err != nil {
		return "", err
	}
	h := hmac.New(func() hash.Hash { return hmac_hash }, buf.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func getTs() int64 {
	un := float64(time.Now().UnixNano()) / float64(1000) / float64(30)
	return int64(math.Floor(un))
}

func GetCurrent2faCode(secretKey string) (string, int64, error) {
	now := time.Now().Unix()
	interval := 30
	t_chunk := (now / int64(interval))

	buf_in := bytes.Buffer{}
	err := binary.Write(&buf_in, binary.BigEndian, int64(t_chunk))
	if err != nil {
		return "", 0, err
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
		return "", 0, err
	}

	code = code & 0x7FFFFFFF

	code = code % 1000000

	i := int64(interval)
	x := (((now + i) / i) * i) - now

	return fmt.Sprintf("%06d", code), x, nil
}

func setScopes(userId int) (*string, error) {

	menus, err := db.Query(`
	SELECT distinct
		menu.id,
		menu.name,
		menu.url,
		menu.parent_menu
	FROM menu
		INNER JOIN tab_to_menu on (tab_to_menu.menu_id = menu.id)
		INNER JOIN resource_to_tab on (resource_to_tab.tab_id = tab_to_menu.tab_id)
		INNER JOIN role_to_resource on (role_to_resource.resource_id = resource_to_tab.resource_id)
		INNER JOIN user_role on (user_role.role_id = role_to_resource.role_id)
	WHERE user_id = $1;`, userId)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var menuArray []struct {
		Id     int
		Name   string
		Url    string
		Parent int
	}

	var (
		id     int
		name   sql.NullString
		url    sql.NullString
		parent int
	)
	for menus.Next() {

		if err := menus.Scan(&id, &name, &url, &parent); err != nil {
			log.Println(err)
			return nil, err
		}

		menuArray = append(menuArray, struct {
			Id     int
			Name   string
			Url    string
			Parent int
		}{
			id,
			name.String,
			url.String,
			parent,
		})

	}

	tabs, err := db.Query(`
	SELECT tab.id,tab.name,tab.url
	FROM tab
	 INNER JOIN resource_to_tab on (resource_to_tab.tab_id = tab.id)
	 INNER JOIN role_to_resource on (role_to_resource.resource_id = resource_to_tab.resource_id)
	 INNER JOIN user_role on (user_role.role_id = role_to_resource.role_id)
	WHERE user_id = $1;`, userId)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var tabArray []struct {
		Id   int
		Name string
		Url  string
	}

	for tabs.Next() {

		if err := tabs.Scan(&id, &name, &url); err != nil {
			log.Println(err)
			return nil, err
		}

		tabArray = append(tabArray, struct {
			Id   int
			Name string
			Url  string
		}{
			id,
			name.String,
			url.String,
		})
	}

	roles, err := db.Query(`
			SELECT role_id
			FROM "user" INNER JOIN "user_role" on (user_role.user_id ="user".id)
			WHERE "user".id = $1;`, userId)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var roleArray []int

	for roles.Next() {

		if err := roles.Scan(&id); err != nil {
			log.Println(err)
			return nil, err
		}

		roleArray = append(roleArray, id)
	}

	s := &Scope{}
	s.Menus = menuArray
	s.Tabs = tabArray
	s.Role = roleArray
	json, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return swag.String(string(json)), nil
}

func CheckScope(scopeUser []string, scopeCheck string) bool {
	for _, v := range scopeUser {
		if v == scopeCheck {
			return true
		}
	}
	return false
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
	// if user_type_id, err := strconv.Atoi(t.Claims.(jwt.MapClaims)["user_type_id"].(string)); err == nil {
	// 	j.User_type_id = user_type_id
	// } else {
	// 	log.Println("parsing user type error:", err)
	// 	return nil, errors.New(500, "system error")
	// }
	// if scope, ok := t.Claims.(jwt.MapClaims)["scope"].(string); ok {
	// 	j.Scope = strings.Split(scope, ",")
	// } else {
	// 	log.Println("parsing user scopes error:", err)
	// 	return nil, errors.New(500, "system error")
	// }
	if s, ok := t.Claims.(jwt.MapClaims)["f2a"].(bool); ok && s {
		j.F2a = true
	}
	if s, ok := t.Claims.(jwt.MapClaims)["reset_password_next_login"].(bool); ok && s {
		j.RequirePassReset = true
	}

	return j, nil
}

type Jwt struct {
	Id_profile, User_type_id int
	F2a                      bool
	RequirePassReset         bool
	Scope                    Scope
}

type Scope struct {
	Role  []int
	Menus []struct {
		Id     int
		Name   string
		Url    string
		Parent int
	}
	Tabs []struct {
		Id   int
		Name string
		Url  string
	}
}
