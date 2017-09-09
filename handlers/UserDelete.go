package handlers

import (
	"log"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
)

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
