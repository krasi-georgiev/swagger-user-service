package handlers

import (
	"log"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
	"golang.org/x/crypto/bcrypt"
)

//PassReset  resets an user password, when old password is not provided the user will be required to change its password upon next login using a temporary password provided by an admin
func PassReset(params operations.PostUserIDPasswordParams, principal interface{}) middleware.Responder {
	j, ok := principal.(*Jwt)
	if !ok {
		return operations.NewPostUserIDPasswordDefault(0)
	}

	// TODO check if the user is trying to change his own password or has permissions to check anyones password
	// prevents changing someone elses password
	if false && int64(j.Id_profile) != params.ID {
		return operations.NewPostUserIDPasswordUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("no permission to change the password for this user")}))
	}

	allowed := false
	if false {
		var password string
		err := db.QueryRow("SELECT password FROM public.user WHERE id=$1", j.Id_profile).Scan(&password)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserIDPasswordDefault(0)
		}
		if bcrypt.CompareHashAndPassword([]byte(password), []byte(params.Body.PasswordOld)) == nil {
			allowed = true
		} else {
			return operations.NewPostUserIDPasswordUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("old password doesn't match")}))
		}
	} else {
		allowed = true
	}
	if allowed {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.PasswordNew), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)

			return operations.NewPostUserIDPasswordDefault(0)
		}
		_, err = db.Exec("UPDATE public.user SET password=$1,reset_password_next_login=true WHERE id=$2 ;", hashedPassword, params.ID)
		if err != nil {
			log.Println(err)
			return operations.NewPostUserIDPasswordDefault(0)
		}
		return operations.NewPostUserIDPasswordOK()

	}
	return operations.NewPostUserIDPasswordUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("don't have permission to change this user password")}))

}

// PassReset resets an user password using a temporary password provided by an admin, once reset you can login as normal using the new password
func PassResetTemp(params operations.PutUserIDPasswordParams) middleware.Responder {
	var tt *Jwt
	if t, err := ParseJwt(*params.Body.Jwt); err != nil {
		log.Println(err)
		return operations.NewPutUserIDPasswordUnauthorized().WithPayload(&models.Response{Code: swag.Int64(int64(err.Code())), Message: swag.String(err.Error())})
	} else {
		tt = t
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*params.Body.PasswordNew), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDPasswordDefault(0)
	}

	_, err = db.Exec("UPDATE public.user SET password=$1,reset_password_next_login=false WHERE id=$2 ;", hashedPassword, tt.Id_profile)
	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDPasswordDefault(0)
	}
	return operations.NewPutUserIDPasswordOK()
}
