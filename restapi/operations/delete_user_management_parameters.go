// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
)

// NewDeleteUserManagementParams creates a new DeleteUserManagementParams object
// with the default values initialized.
func NewDeleteUserManagementParams() DeleteUserManagementParams {
	var ()
	return DeleteUserManagementParams{}
}

// DeleteUserManagementParams contains all the bound params for the delete user management operation
// typically these are obtained from a http.Request
//
// swagger:parameters DeleteUserManagement
type DeleteUserManagementParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request

	/*
	  In: body
	*/
	Body DeleteUserManagementBody
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls
func (o *DeleteUserManagementParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error
	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body DeleteUserManagementBody
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			res = append(res, errors.NewParseError("body", "body", "", err))
		} else {

			if len(res) == 0 {
				o.Body = body
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
