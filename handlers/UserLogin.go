package handlers

import (
	"database/sql"
	"log"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
	"golang.org/x/crypto/bcrypt"
)

// UserLogin is the endpoint used for authenticating and  generating a jwt token.
func UserLogin(params operations.PostUserLoginParams) middleware.Responder {
	rows, err := db.Query("SELECT id,password,active,reset_password_next_login,f2a,f2a_enforced FROM public.user WHERE username=$1", params.Body.Username)

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
	var f2a_enforced sql.NullBool

	for rows.Next() {

		if err := rows.Scan(&id, &password, &active, &reset_password_next_login, &f2a, &f2a_enforced); err != nil {
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
			if reset_password_next_login.Bool { // user is required to change their password
				t["reset_password_next_login"] = true
			}
			if f2a_enforced.Bool { // user is required to enable 2fa
				t["f2a_enforced"] = true
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
			tt, err := token.SignedString(SignKey)
			if err != nil {
				return operations.NewPostUserLoginDefault(0)
			}
			if f2a.Valid {
				return operations.NewPostUserLoginPartialContent().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
			}
			if reset_password_next_login.Bool { // returns only a temporary jwt token that will need extra unlocking
				return operations.NewPostUserLoginCreated().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
			}
			if f2a_enforced.Bool { // returns only a temporary jwt token that will need extra unlocking
				return operations.NewPostUserLoginAccepted().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
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

}
