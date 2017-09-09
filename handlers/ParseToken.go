package handlers

import (
	"database/sql"
	"log"

	"github.com/go-openapi/runtime/middleware"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
)

//ParseToken checks it against the database and returns a json array with all details about a given user
func ParseToken(params operations.PutUserLoginParams, principal interface{}) middleware.Responder {
	t, ok := principal.(*Jwt)
	if !ok {
		return operations.NewPutUserIDDefault(0)
	}

	var id int64
	var username string
	var tenant_id int64
	var f2a bool
	var active bool
	var created string
	var reset_password_next_login bool
	var person_id sql.NullInt64
	var email sql.NullString
	var voice bool

	err := db.QueryRow(`SELECT 
		id,
		username,
		tenant_id,
		CASE WHEN f2a IS NULL THEN true ELSE false end as f2a,
		active,
		created,
		reset_password_next_login,
		person_id,
		email,
		voice 
		FROM public.user WHERE id=$1`, t.Id_profile).Scan(
		&id,
		&username, &tenant_id,
		&f2a, &active,
		&created,
		&reset_password_next_login,
		&person_id,
		&email,
		&voice,
	)

	if err != nil {
		log.Println(err)
		return operations.NewPutUserLoginDefault(0)
	}

	var personID *int64
	if person_id.Valid {
		personID = &person_id.Int64
	} else {
		personID = nil
	}
	return operations.NewPutUserLoginOK().WithPayload(operations.PutUserLoginOKBody{
		Active:                 &active,
		Created:                &created,
		Email:                  &email.String,
		F2a:                    &f2a,
		ID:                     &id,
		PersonID:               personID,
		ResetPasswordNextLogin: &reset_password_next_login,
		TenantID:               &tenant_id,
		Username:               &username,
		Voice:                  &voice,
	})

}
