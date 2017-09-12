// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/vanderbr/choicehealth_user-service/models"
)

// GetUserF2aOKCode is the HTTP code returned for type GetUserF2aOK
const GetUserF2aOKCode int = 200

/*GetUserF2aOK The  2fa qr image needed to be scanned by the google authenticator app. The secrets needs to be passed back to the 2fa enabling api

swagger:response getUserF2aOK
*/
type GetUserF2aOK struct {

	/*
	  In: Body
	*/
	Payload GetUserF2aOKBody `json:"body,omitempty"`
}

// NewGetUserF2aOK creates GetUserF2aOK with default headers values
func NewGetUserF2aOK() *GetUserF2aOK {
	return &GetUserF2aOK{}
}

// WithPayload adds the payload to the get user f2a o k response
func (o *GetUserF2aOK) WithPayload(payload GetUserF2aOKBody) *GetUserF2aOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get user f2a o k response
func (o *GetUserF2aOK) SetPayload(payload GetUserF2aOKBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetUserF2aOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}

/*GetUserF2aDefault Generic Error used for most error responses - it returns a custom code and message depending on the reply context

swagger:response getUserF2aDefault
*/
type GetUserF2aDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewGetUserF2aDefault creates GetUserF2aDefault with default headers values
func NewGetUserF2aDefault(code int) *GetUserF2aDefault {
	if code <= 0 {
		code = 500
	}

	return &GetUserF2aDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the get user f2a default response
func (o *GetUserF2aDefault) WithStatusCode(code int) *GetUserF2aDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the get user f2a default response
func (o *GetUserF2aDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the get user f2a default response
func (o *GetUserF2aDefault) WithPayload(payload *models.Response) *GetUserF2aDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get user f2a default response
func (o *GetUserF2aDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetUserF2aDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
