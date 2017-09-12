package handlers

import (
	"log"
	"net/mail"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
)

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
