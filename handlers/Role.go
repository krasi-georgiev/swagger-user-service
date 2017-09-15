package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"strconv"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
)

//RoleDelete deletes a role with give id
func RoleDelete(params operations.DeleteUserRoleIDParams, principal interface{}) middleware.Responder {
	r, err := db.Exec("DELETE FROM role WHERE id=$1 ;", params.ID)
	if err != nil {
		log.Println(err)
		return operations.NewDeleteUserRoleIDDefault(0)
	}
	if count, err := r.RowsAffected(); err != nil || count == 0 {
		return operations.NewDeleteUserRoleIDDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("invalid role id")}))

	}
	return operations.NewDeleteUserRoleIDOK()
}

//Roles List all user roles
func Roles(params operations.GetUserRolesParams, principal interface{}) middleware.Responder {

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
		return operations.NewGetUserRolesDefault(0)
	}
	var roles []*operations.GetUserRolesOKBodyItems0
	for rows.Next() {
		var (
			id         int64
			name, data sql.NullString
		)
		if err := rows.Scan(&id, &name, &data); err != nil {
			log.Println(err)
			return operations.NewGetUserRolesDefault(0)
		}
		roles = append(roles, &operations.GetUserRolesOKBodyItems0{ID: id, Name: name.String, Data: data.String})
	}

	return operations.NewGetUserRolesOK().WithPayload(roles)
}

//RoleCreate Creates a new Role
func RoleCreate(params operations.PostUserRoleParams, principal interface{}) middleware.Responder {
	var id int64
	var js json.RawMessage
	if err := json.Unmarshal([]byte(*params.Body.Data), &js); err != nil {
		return operations.NewPostUserRoleDefault(400).WithPayload((&models.Response{Code: swag.Int64(400), Message: swag.String("invalid json for the data field")}))
	}
	err := db.QueryRow("INSERT INTO role (name,data)	VALUES ($1,$2)	RETURNING id", *params.Body.Name, *params.Body.Data).Scan(&id)
	if err != nil {
		log.Println(err)
		return operations.NewPostUserRoleDefault(0)
	}
	return operations.NewPostUserRoleOK().WithPayload(operations.PostUserRoleOKBody{ID: &id})
}

// RoleUpdate updates a give role by id
func RoleUpdate(params operations.PutUserRoleIDParams, principal interface{}) middleware.Responder {
	var js json.RawMessage
	if err := json.Unmarshal([]byte(*params.Body.Data), &js); err != nil {
		return operations.NewPutUserRoleIDDefault(400).WithPayload((&models.Response{Code: swag.Int64(400), Message: swag.String("invalid json for the data field")}))
	}
	result, err := db.Exec("UPDATE role SET name=$1,data=$2 WHERE id=$3 ;", params.Body.Name, params.Body.Data, params.ID)
	if err != nil {
		log.Println(err)
		return operations.NewPutUserRoleIDDefault(0)
	}
	if count, err := result.RowsAffected(); err != nil || count == 0 {
		return operations.NewPutUserRoleIDDefault(404).WithPayload((&models.Response{Code: swag.Int64(404), Message: swag.String("role id not found")}))
	}
	return operations.NewPutUserRoleIDOK()
}
