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

// GetUser2faHandlerFunc turns a function with the right signature into a get user2fa handler
type GetUser2faHandlerFunc func(GetUser2faParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetUser2faHandlerFunc) Handle(params GetUser2faParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetUser2faHandler interface for that can handle valid get user2fa params
type GetUser2faHandler interface {
	Handle(GetUser2faParams, interface{}) middleware.Responder
}

// NewGetUser2fa creates a new http.Handler for the get user2fa operation
func NewGetUser2fa(ctx *middleware.Context, handler GetUser2faHandler) *GetUser2fa {
	return &GetUser2fa{Context: ctx, Handler: handler}
}

/*GetUser2fa swagger:route GET /user/2fa getUser2fa

generate qr base64 encoded image and master code for the user to scan with the google authenticator and add it to the phone app

*/
type GetUser2fa struct {
	Context *middleware.Context
	Handler GetUser2faHandler
}

func (o *GetUser2fa) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetUser2faParams()

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

// GetUser2faOKBody get user2fa o k body
// swagger:model GetUser2faOKBody
type GetUser2faOKBody struct {

	// qr
	// Required: true
	Qr *string `json:"qr"`

	// secret
	// Required: true
	Secret *string `json:"secret"`
}

// Validate validates this get user2fa o k body
func (o *GetUser2faOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateQr(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := o.validateSecret(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *GetUser2faOKBody) validateQr(formats strfmt.Registry) error {

	if err := validate.Required("getUser2faOK"+"."+"qr", "body", o.Qr); err != nil {
		return err
	}

	return nil
}

func (o *GetUser2faOKBody) validateSecret(formats strfmt.Registry) error {

	if err := validate.Required("getUser2faOK"+"."+"secret", "body", o.Secret); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (o *GetUser2faOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *GetUser2faOKBody) UnmarshalBinary(b []byte) error {
	var res GetUser2faOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}