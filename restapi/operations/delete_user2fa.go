// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
	swag "github.com/go-openapi/swag"
)

// DeleteUser2faHandlerFunc turns a function with the right signature into a delete user2fa handler
type DeleteUser2faHandlerFunc func(DeleteUser2faParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn DeleteUser2faHandlerFunc) Handle(params DeleteUser2faParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// DeleteUser2faHandler interface for that can handle valid delete user2fa params
type DeleteUser2faHandler interface {
	Handle(DeleteUser2faParams, interface{}) middleware.Responder
}

// NewDeleteUser2fa creates a new http.Handler for the delete user2fa operation
func NewDeleteUser2fa(ctx *middleware.Context, handler DeleteUser2faHandler) *DeleteUser2fa {
	return &DeleteUser2fa{Context: ctx, Handler: handler}
}

/*DeleteUser2fa swagger:route DELETE /user/2fa deleteUser2fa

disable 2 factor authenticaiton for an account

*/
type DeleteUser2fa struct {
	Context *middleware.Context
	Handler DeleteUser2faHandler
}

func (o *DeleteUser2fa) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewDeleteUser2faParams()

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

// DeleteUser2faBody delete user2fa body
// swagger:model DeleteUser2faBody
type DeleteUser2faBody struct {

	// id profile
	// Required: true
	IDProfile *string `json:"id_profile"`

	// password
	// Required: true
	Password *string `json:"password"`
}

// MarshalBinary interface implementation
func (o *DeleteUser2faBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *DeleteUser2faBody) UnmarshalBinary(b []byte) error {
	var res DeleteUser2faBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}