// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/choicehealth/user-service/models"
)

// PutUser2faOKCode is the HTTP code returned for type PutUser2faOK
const PutUser2faOKCode int = 200

/*PutUser2faOK 2fa enabled.

swagger:response putUser2faOK
*/
type PutUser2faOK struct {
}

// NewPutUser2faOK creates PutUser2faOK with default headers values
func NewPutUser2faOK() *PutUser2faOK {
	return &PutUser2faOK{}
}

// WriteResponse to the client
func (o *PutUser2faOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
}

// PutUser2faUnauthorizedCode is the HTTP code returned for type PutUser2faUnauthorized
const PutUser2faUnauthorizedCode int = 401

/*PutUser2faUnauthorized Authentication is missing or invalid

swagger:response putUser2faUnauthorized
*/
type PutUser2faUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPutUser2faUnauthorized creates PutUser2faUnauthorized with default headers values
func NewPutUser2faUnauthorized() *PutUser2faUnauthorized {
	return &PutUser2faUnauthorized{}
}

// WithPayload adds the payload to the put user2fa unauthorized response
func (o *PutUser2faUnauthorized) WithPayload(payload *models.Response) *PutUser2faUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put user2fa unauthorized response
func (o *PutUser2faUnauthorized) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutUser2faUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*PutUser2faDefault Unexpected error

swagger:response putUser2faDefault
*/
type PutUser2faDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPutUser2faDefault creates PutUser2faDefault with default headers values
func NewPutUser2faDefault(code int) *PutUser2faDefault {
	if code <= 0 {
		code = 500
	}

	return &PutUser2faDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the put user2fa default response
func (o *PutUser2faDefault) WithStatusCode(code int) *PutUser2faDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the put user2fa default response
func (o *PutUser2faDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the put user2fa default response
func (o *PutUser2faDefault) WithPayload(payload *models.Response) *PutUser2faDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put user2fa default response
func (o *PutUser2faDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutUser2faDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}