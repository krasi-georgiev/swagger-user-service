// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	errors "github.com/go-openapi/errors"
	middleware "github.com/go-openapi/runtime/middleware"
	strfmt "github.com/go-openapi/strfmt"
	swag "github.com/go-openapi/swag"
)

// GetUsersHandlerFunc turns a function with the right signature into a get users handler
type GetUsersHandlerFunc func(GetUsersParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetUsersHandlerFunc) Handle(params GetUsersParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetUsersHandler interface for that can handle valid get users params
type GetUsersHandler interface {
	Handle(GetUsersParams, interface{}) middleware.Responder
}

// NewGetUsers creates a new http.Handler for the get users operation
func NewGetUsers(ctx *middleware.Context, handler GetUsersHandler) *GetUsers {
	return &GetUsers{Context: ctx, Handler: handler}
}

/*GetUsers swagger:route GET /users getUsers

generates a list of users

*/
type GetUsers struct {
	Context *middleware.Context
	Handler GetUsersHandler
}

func (o *GetUsers) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetUsersParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}

// GetUsersOKBodyItems0 get users o k body items0
// swagger:model GetUsersOKBodyItems0

type GetUsersOKBodyItems0 struct {

	// created
	Created string `json:"created,omitempty"`

	// f2a
	F2a int64 `json:"f2a,omitempty"`

	// id
	ID int64 `json:"id,omitempty"`

	// username
	Username string `json:"username,omitempty"`

	// voice
	Voice int64 `json:"voice,omitempty"`
}

/* polymorph GetUsersOKBodyItems0 created false */

/* polymorph GetUsersOKBodyItems0 f2a false */

/* polymorph GetUsersOKBodyItems0 id false */

/* polymorph GetUsersOKBodyItems0 username false */

/* polymorph GetUsersOKBodyItems0 voice false */

// Validate validates this get users o k body items0
func (o *GetUsersOKBodyItems0) Validate(formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (o *GetUsersOKBodyItems0) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetUsersOKBodyItems0) UnmarshalBinary(b []byte) error {
	var res GetUsersOKBodyItems0
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}