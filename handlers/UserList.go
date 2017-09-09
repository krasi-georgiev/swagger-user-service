package handlers

import (
	"database/sql"
	"log"
	"strconv"

	"github.com/go-openapi/runtime/middleware"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
)

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
