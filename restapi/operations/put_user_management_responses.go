// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/vanderbr/choicehealth_user-service/models"
)

// PutUserManagementOKCode is the HTTP code returned for type PutUserManagementOK
const PutUserManagementOKCode int = 200

/*PutUserManagementOK put user management o k

swagger:response putUserManagementOK
*/
type PutUserManagementOK struct {
}

// NewPutUserManagementOK creates PutUserManagementOK with default headers values
func NewPutUserManagementOK() *PutUserManagementOK {
	return &PutUserManagementOK{}
}

// WriteResponse to the client
func (o *PutUserManagementOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
}

// PutUserManagementUnauthorizedCode is the HTTP code returned for type PutUserManagementUnauthorized
const PutUserManagementUnauthorizedCode int = 401

/*PutUserManagementUnauthorized Authentication is missing or invalid

swagger:response putUserManagementUnauthorized
*/
type PutUserManagementUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPutUserManagementUnauthorized creates PutUserManagementUnauthorized with default headers values
func NewPutUserManagementUnauthorized() *PutUserManagementUnauthorized {
	return &PutUserManagementUnauthorized{}
}

// WithPayload adds the payload to the put user management unauthorized response
func (o *PutUserManagementUnauthorized) WithPayload(payload *models.Response) *PutUserManagementUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put user management unauthorized response
func (o *PutUserManagementUnauthorized) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutUserManagementUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*PutUserManagementDefault Generic Error used for most error responses - it returns a custom code and message depending on the reply context

swagger:response putUserManagementDefault
*/
type PutUserManagementDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPutUserManagementDefault creates PutUserManagementDefault with default headers values
func NewPutUserManagementDefault(code int) *PutUserManagementDefault {
	if code <= 0 {
		code = 500
	}

	return &PutUserManagementDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the put user management default response
func (o *PutUserManagementDefault) WithStatusCode(code int) *PutUserManagementDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the put user management default response
func (o *PutUserManagementDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the put user management default response
func (o *PutUserManagementDefault) WithPayload(payload *models.Response) *PutUserManagementDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put user management default response
func (o *PutUserManagementDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutUserManagementDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
