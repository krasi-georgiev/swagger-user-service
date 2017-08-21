// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/choicehealth/user-service/models"
)

// PostUserPasswordOKCode is the HTTP code returned for type PostUserPasswordOK
const PostUserPasswordOKCode int = 200

/*PostUserPasswordOK shows a message if the password was changed or sent with an email reminder.

swagger:response postUserPasswordOK
*/
type PostUserPasswordOK struct {
}

// NewPostUserPasswordOK creates PostUserPasswordOK with default headers values
func NewPostUserPasswordOK() *PostUserPasswordOK {
	return &PostUserPasswordOK{}
}

// WriteResponse to the client
func (o *PostUserPasswordOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
}

/*PostUserPasswordDefault Unexpected error

swagger:response postUserPasswordDefault
*/
type PostUserPasswordDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPostUserPasswordDefault creates PostUserPasswordDefault with default headers values
func NewPostUserPasswordDefault(code int) *PostUserPasswordDefault {
	if code <= 0 {
		code = 500
	}

	return &PostUserPasswordDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the post user password default response
func (o *PostUserPasswordDefault) WithStatusCode(code int) *PostUserPasswordDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the post user password default response
func (o *PostUserPasswordDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the post user password default response
func (o *PostUserPasswordDefault) WithPayload(payload *models.Response) *PostUserPasswordDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post user password default response
func (o *PostUserPasswordDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostUserPasswordDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
