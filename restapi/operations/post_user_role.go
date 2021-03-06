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
	validate "github.com/go-openapi/validate"
)

// PostUserRoleHandlerFunc turns a function with the right signature into a post user role handler
type PostUserRoleHandlerFunc func(PostUserRoleParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn PostUserRoleHandlerFunc) Handle(params PostUserRoleParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// PostUserRoleHandler interface for that can handle valid post user role params
type PostUserRoleHandler interface {
	Handle(PostUserRoleParams, interface{}) middleware.Responder
}

// NewPostUserRole creates a new http.Handler for the post user role operation
func NewPostUserRole(ctx *middleware.Context, handler PostUserRoleHandler) *PostUserRole {
	return &PostUserRole{Context: ctx, Handler: handler}
}

/*PostUserRole swagger:route POST /user/role postUserRole

creates a new role

*/
type PostUserRole struct {
	Context *middleware.Context
	Handler PostUserRoleHandler
}

func (o *PostUserRole) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewPostUserRoleParams()

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

// PostUserRoleOKBody post user role o k body
// swagger:model PostUserRoleOKBody

type PostUserRoleOKBody struct {

	// id
	// Required: true
	ID *int64 `json:"id"`
}

/* polymorph PostUserRoleOKBody id false */

// Validate validates this post user role o k body
func (o *PostUserRoleOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateID(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PostUserRoleOKBody) validateID(formats strfmt.Registry) error {

	if err := validate.Required("postUserRoleOK"+"."+"id", "body", o.ID); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *PostUserRoleOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostUserRoleOKBody) UnmarshalBinary(b []byte) error {
	var res PostUserRoleOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
