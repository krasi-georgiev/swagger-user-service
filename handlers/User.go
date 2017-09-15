package handlers

import (
	"database/sql"
	"log"
	"net/mail"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
)

// UserUpdate updates a given user
func UserUpdate(params operations.PutUserIDParams, principal interface{}) middleware.Responder {

	tx, err := db.Begin()
	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDDefault(0)
	}

	if params.Body.Password != "" {
		var hashedPassword []byte
		hashedPassword, err = bcrypt.GenerateFromPassword([]byte(params.Body.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserIDDefault(0)
		}
		_, err = tx.Exec("UPDATE public.user SET password=$1  WHERE id=$2;", hashedPassword, params.ID)

	}

	if params.Body.Active != "" {
		var active bool
		switch params.Body.Active {
		case "true":
			active = true
		default:
			active = false
		}
		_, err = tx.Exec("UPDATE public.user SET active=$1  WHERE id=$2;", active, params.ID)

	}

	if params.Body.Voice != "" {
		var voice bool
		switch params.Body.Voice {
		case "true":
			voice = true
		default:
			voice = false
		}
		_, err = tx.Exec("UPDATE public.user SET voice=$1  WHERE id=$2;", voice, params.ID)
	}

	if params.Body.F2aEnforce != "" {
		var F2aEnforce bool
		switch params.Body.F2aEnforce {
		case "true":
			F2aEnforce = true
		default:
			F2aEnforce = false
		}
		_, err = tx.Exec("UPDATE public.user SET f2a_enforced=$1  WHERE id=$2;", F2aEnforce, params.ID)
		_, err = tx.Exec("UPDATE public.user SET f2a=NULL  WHERE id=$1;", params.ID)
	}

	if params.Body.Email != "" {
		_, err = tx.Exec("UPDATE public.user SET email=$1  WHERE id=$2;", params.Body.Email, params.ID)
	}

	if params.Body.PersonID > 0 {
		_, err = tx.Exec("UPDATE public.user SET person_id=$1  WHERE id=$2;", params.Body.PersonID, params.ID)
	}

	if params.Body.ResetPasswordNextLogin != "" {
		var reset bool
		switch params.Body.ResetPasswordNextLogin {
		case "true":
			reset = true
		default:
			reset = false
		}
		_, err = tx.Exec("UPDATE public.user SET reset_password_next_login=$1  WHERE id=$2;", reset, params.ID)
	}

	if params.Body.TenantID > 0 {
		_, err = tx.Exec("UPDATE public.user SET tenant_id=$1  WHERE id=$2;", params.Body.TenantID, params.ID)
	}

	if len(params.Body.Role) > 0 {
		_, err = tx.Exec("DELETE FROM user_role WHERE user_id=$1;", params.ID)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserIDDefault(0)
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
			return operations.NewPutUserIDDefault(0)
		}
		if count, err := result.RowsAffected(); err != nil || count < int64(len(params.Body.Role)) {
			return operations.NewPutUserIDDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("role array includes invalid id")}))
		}

		roles := ""
		for _, v := range params.Body.Role {
			roles = roles + "(" + strconv.Itoa(int(params.ID)) + ", " + strconv.Itoa(int(v)) + "),"
		}
		// remove the last comma
		roles = roles[:len(roles)-1]
		_, err = tx.Exec("INSERT INTO user_role (user_id,role_id)	VALUES " + roles + ";")
	}

	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDDefault(0)
	}

	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		log.Println(err)
		return operations.NewPutUserIDDefault(0)
	}

	if params.Body.Username != "" {
		// before updating make sure the same username doesn't already exist
		rows, err := db.Query("SELECT id FROM public.user WHERE username=$1 AND id != $2", params.Body.Username, params.ID)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserIDDefault(0)
		}
		defer rows.Close()

		for rows.Next() {
			return operations.NewPutUserIDDefault(409).WithPayload(&models.Response{Code: swag.Int64(409), Message: swag.String("username  already exists")})
		}

		_, err = db.Exec("UPDATE public.user SET username=$1  WHERE id=$2;", params.Body.Username, params.ID)
	}

	return operations.NewPutUserIDOK()

}

// UserCreate creates a new user
func UserCreate(params operations.PostUserParams, principal interface{}) middleware.Responder {

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
		return operations.NewPostUserDefault(0)
	}
	defer rows.Close()

	for rows.Next() {
		return operations.NewPostUserConflict().WithPayload(&models.Response{Code: swag.Int64(409), Message: swag.String("user already exists")})
	}

	email := ""
	if params.Body.Email != "" {
		e, err := mail.ParseAddress(params.Body.Email)
		if err != nil {
			return operations.NewPostUserConflict().WithPayload(&models.Response{Code: swag.Int64(409), Message: swag.String("invalid email")})
		}
		email = e.Address
	}

	var id int64
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		return operations.NewPostUserDefault(0)

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
		return operations.NewPostUserDefault(0)
	}
	if count, err := result.RowsAffected(); err != nil || count < int64(len(params.Body.Role)) {
		return operations.NewPostUserDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("role array includes invalid id")}))
	}

	roles := ""
	for _, v := range params.Body.Role {
		roles = roles + "((SELECT id FROM profileInsert), " + strconv.Itoa(int(v)) + "),"
	}
	// remove the last comma
	roles = roles[:len(roles)-1]
	query := `
				WITH profileInsert as (
					INSERT INTO public.user (username,email,active,voice, password,tenant_id,created,reset_password_next_login,person_id,f2a_enforced)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)	RETURNING id),
					insertProfileRole as (
						INSERT INTO user_role (user_id,role_id)
						VALUES ` + roles + `
						)
					SELECT * FROM profileInsert`

	err = db.QueryRow(query, *params.Body.Username, email, params.Body.Active, params.Body.Voice, hashedPassword, params.Body.TenantID, time.Now(), params.Body.ResetPasswordNextLogin, params.Body.PersonID, params.Body.F2aEnforced).Scan(&id)
	if err != nil {
		log.Println(err)
		return operations.NewPostUserDefault(0)
	}
	return operations.NewPostUserOK().WithPayload(operations.PostUserOKBody{ID: &id})

}

// UserDelete deletes a given user
func UserDelete(params operations.DeleteUserIDParams, principal interface{}) middleware.Responder {

	if params.ID < 1 {
		return operations.NewDeleteUserIDDefault(400).WithPayload(&models.Response{Code: swag.Int64(400), Message: swag.String("invalid profile id")})
	}

	tx, err := db.Begin()
	if err != nil {
		log.Println(err)
		return operations.NewPostUserDefault(0)
	}

	_, err = tx.Exec("DELETE FROM user_role WHERE user_id=$1;", params.ID)
	if err != nil {
		log.Println(err)
		return operations.NewDeleteUserIDDefault(0)
	}

	result, err := tx.Exec("DELETE FROM public.user WHERE id=$1 ;", params.ID)
	if err != nil {
		log.Println(err)
		return operations.NewDeleteUserIDDefault(0)
	}

	err = tx.Commit()
	if err != nil {
		log.Println(err)
		return operations.NewDeleteUserIDDefault(0)
	}
	if count, err := result.RowsAffected(); err != nil || count == 0 {
		return operations.NewDeleteUserIDDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("user with this id doesn't exist")}))
	}

	return operations.NewDeleteUserIDOK()
}

// UserList returns an array of users
func UserList(params operations.GetUsersParams, principal interface{}) middleware.Responder {
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
	if params.Voice != nil && *params.Voice == true {
		voiceFilter = " WHERE  voice is TRUE"
	}

	rows, err := db.Query("select id, username,created,CASE WHEN voice IS false THEN -1 ELSE 1 end as voice,CASE WHEN f2a IS NULL THEN -1 ELSE 1 end as f2a from public.user" + voiceFilter + limit + offset + ";")
	if err != nil {
		log.Println(err)
		return operations.NewGetUsersDefault(0)
	}
	var users []*operations.GetUsersOKBodyItems0
	for rows.Next() {
		if err := rows.Scan(&id, &username, &created, &voice, &f2a); err != nil {
			log.Println(err)
			return operations.NewGetUsersDefault(0)
		}
		users = append(users, &operations.GetUsersOKBodyItems0{Created: created.String, Voice: voice, F2a: f2a, ID: id, Username: username.String})

	}
	return operations.NewGetUsersOK().WithPayload(users)
}

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

func UserDetails(params operations.GetUserIDParams, principal interface{}) middleware.Responder {
	var (
		id                        int64
		username                  sql.NullString
		email                     sql.NullString
		active                    sql.NullBool
		voice                     sql.NullBool
		tenant_id                 sql.NullInt64
		created                   sql.NullString
		reset_password_next_login sql.NullBool
		person_id                 sql.NullInt64
		f2a_enforced              sql.NullBool
	)
	err := db.QueryRow(` 
		SELECT
		id,                      
		username,                  
		email,                 
		active,                
		voice,               
		tenant_id,              
		created,             
		reset_password_next_login, 
		person_id, 
		f2a_enforced
		FROM public.user
		WHERE id=$1`, params.ID).Scan(
		&id,
		&username,
		&email,
		&active,
		&voice,
		&tenant_id,
		&created,
		&reset_password_next_login,
		&person_id,
		&f2a_enforced,
	)
	if err != nil {
		return operations.NewGetUserIDDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String(err.Error())}))

	}

	return operations.NewGetUserIDOK().WithPayload(&models.Profile{
		Active:                 &active.Bool,
		Email:                  email.String,
		F2aEnforced:            f2a_enforced.Bool,
		PersonID:               &person_id.Int64,
		ResetPasswordNextLogin: &reset_password_next_login.Bool,
		TenantID:               &tenant_id.Int64,
		Username:               &username.String,
		Voice:                  voice.Bool,
	})

}
