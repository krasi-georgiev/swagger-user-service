// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
	swag "github.com/go-openapi/swag"
)

// PostUser2faHandlerFunc turns a function with the right signature into a post user2fa handler
type PostUser2faHandlerFunc func(PostUser2faParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PostUser2faHandlerFunc) Handle(params PostUser2faParams) middleware.Responder {
	return fn(params)
}

// PostUser2faHandler interface for that can handle valid post user2fa params
type PostUser2faHandler interface {
	Handle(PostUser2faParams) middleware.Responder
}

// NewPostUser2fa creates a new http.Handler for the post user2fa operation
func NewPostUser2fa(ctx *middleware.Context, handler PostUser2faHandler) *PostUser2fa {
	return &PostUser2fa{Context: ctx, Handler: handler}
}

/*PostUser2fa swagger:route POST /user/2fa postUser2fa

used when the account is with 2 factor authentication enabled. use the login endpoint first to get the initial jwt token and than use this endpoint to get the second jwt token after providing a valid google authenticator code

*/
type PostUser2fa struct {
	Context *middleware.Context
	Handler PostUser2faHandler
}

func (o *PostUser2fa) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewPostUser2faParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}

// PostUser2faBody post user2fa body
// swagger:model PostUser2faBody
type PostUser2faBody struct {

	// the  2 factor time code accuired from the google authenticator app
	// Required: true
	F2a *string `json:"f2a"`

	// the jwt token accuired form the initial login
	// Required: true
	Jwt *string `json:"jwt"`
}

// MarshalBinary interface implementation
func (o *PostUser2faBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PostUser2faBody) UnmarshalBinary(b []byte) error {
	var res PostUser2faBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}