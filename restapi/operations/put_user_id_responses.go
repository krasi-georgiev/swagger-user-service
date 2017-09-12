// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/vanderbr/choicehealth_user-service/models"
)

// PutUserIDOKCode is the HTTP code returned for type PutUserIDOK
const PutUserIDOKCode int = 200

/*PutUserIDOK Generic Ok Response - it returns a custom code and message depending on the reply context

swagger:response putUserIdOK
*/
type PutUserIDOK struct {

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPutUserIDOK creates PutUserIDOK with default headers values
func NewPutUserIDOK() *PutUserIDOK {
	return &PutUserIDOK{}
}

// WithPayload adds the payload to the put user Id o k response
func (o *PutUserIDOK) WithPayload(payload *models.Response) *PutUserIDOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put user Id o k response
func (o *PutUserIDOK) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutUserIDOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*PutUserIDDefault Generic Error used for most error responses - it returns a custom code and message depending on the reply context

swagger:response putUserIdDefault
*/
type PutUserIDDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPutUserIDDefault creates PutUserIDDefault with default headers values
func NewPutUserIDDefault(code int) *PutUserIDDefault {
	if code <= 0 {
		code = 500
	}

	return &PutUserIDDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the put user ID default response
func (o *PutUserIDDefault) WithStatusCode(code int) *PutUserIDDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the put user ID default response
func (o *PutUserIDDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the put user ID default response
func (o *PutUserIDDefault) WithPayload(payload *models.Response) *PutUserIDDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put user ID default response
func (o *PutUserIDDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutUserIDDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
