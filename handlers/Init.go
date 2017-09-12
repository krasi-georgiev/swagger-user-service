package handlers

import (
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"strconv"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	_ "github.com/lib/pq"
)

var (
	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
	db        *sql.DB
)

func init() {

	if d, err := sql.Open("postgres", "postgres://"+os.Getenv("DB_USER")+":"+os.Getenv("DB_PASS")+"@"+os.Getenv("DB_HOST")+"/choicehealth?sslmode=disable"); err != nil {
		log.Fatalf("error connecting to the DB :%v", err)
	} else {
		db = d
	}
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

	s := &scope{}
	s.Menus = menuArray
	s.Tabs = tabArray
	s.Role = roleArray
	json, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return swag.String(string(json)), nil
}

type Jwt struct {
	Id_profile, User_type_id int
	F2a                      bool
	RequirePassReset         bool
	RequireF2Enable          bool
	Scope                    scope
}

type scope struct {
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

func ParseJwt(token string) (*Jwt, errors.Error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return VerifyKey, nil
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

	if s, ok := t.Claims.(jwt.MapClaims)["f2a"].(bool); ok && s {
		j.F2a = true
	}
	if s, ok := t.Claims.(jwt.MapClaims)["reset_password_next_login"].(bool); ok && s {
		j.RequirePassReset = true
	}
	if s, ok := t.Claims.(jwt.MapClaims)["f2a_enforced"].(bool); ok && s {
		j.RequireF2Enable = true
	}

	return j, nil
}
