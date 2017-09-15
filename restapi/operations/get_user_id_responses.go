// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/vanderbr/choicehealth_user-service/models"
)

// GetUserIDOKCode is the HTTP code returned for type GetUserIDOK
const GetUserIDOKCode int = 200

/*GetUserIDOK user item

swagger:response getUserIdOK
*/
type GetUserIDOK struct {

	/*
	  In: Body
	*/
	Payload *models.Profile `json:"body,omitempty"`
}

// NewGetUserIDOK creates GetUserIDOK with default headers values
func NewGetUserIDOK() *GetUserIDOK {
	return &GetUserIDOK{}
}

// WithPayload adds the payload to the get user Id o k response
func (o *GetUserIDOK) WithPayload(payload *models.Profile) *GetUserIDOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get user Id o k response
func (o *GetUserIDOK) SetPayload(payload *models.Profile) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetUserIDOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*GetUserIDDefault Generic Error used for most error responses - it returns a custom code and message depending on the reply context

swagger:response getUserIdDefault
*/
type GetUserIDDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewGetUserIDDefault creates GetUserIDDefault with default headers values
func NewGetUserIDDefault(code int) *GetUserIDDefault {
	if code <= 0 {
		code = 500
	}

	return &GetUserIDDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the get user ID default response
func (o *GetUserIDDefault) WithStatusCode(code int) *GetUserIDDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the get user ID default response
func (o *GetUserIDDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the get user ID default response
func (o *GetUserIDDefault) WithPayload(payload *models.Response) *GetUserIDDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get user ID default response
func (o *GetUserIDDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetUserIDDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
