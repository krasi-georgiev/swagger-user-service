package handlers

import (
	"log"
	"strconv"

	"golang.org/x/crypto/bcrypt"

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
