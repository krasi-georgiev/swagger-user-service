// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/vanderbr/choicehealth_user-service/models"
)

// PostUser2faOKCode is the HTTP code returned for type PostUser2faOK
const PostUser2faOKCode int = 200

/*PostUser2faOK the new jwt token that can be used for all endpoints.

swagger:response postUser2faOK
*/
type PostUser2faOK struct {

	/*
	  In: Body
	*/
	Payload *models.Jwt `json:"body,omitempty"`
}

// NewPostUser2faOK creates PostUser2faOK with default headers values
func NewPostUser2faOK() *PostUser2faOK {
	return &PostUser2faOK{}
}

// WithPayload adds the payload to the post user2fa o k response
func (o *PostUser2faOK) WithPayload(payload *models.Jwt) *PostUser2faOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post user2fa o k response
func (o *PostUser2faOK) SetPayload(payload *models.Jwt) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostUser2faOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostUser2faUnauthorizedCode is the HTTP code returned for type PostUser2faUnauthorized
const PostUser2faUnauthorizedCode int = 401

/*PostUser2faUnauthorized Authentication is missing or invalid

swagger:response postUser2faUnauthorized
*/
type PostUser2faUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPostUser2faUnauthorized creates PostUser2faUnauthorized with default headers values
func NewPostUser2faUnauthorized() *PostUser2faUnauthorized {
	return &PostUser2faUnauthorized{}
}

// WithPayload adds the payload to the post user2fa unauthorized response
func (o *PostUser2faUnauthorized) WithPayload(payload *models.Response) *PostUser2faUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post user2fa unauthorized response
func (o *PostUser2faUnauthorized) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostUser2faUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*PostUser2faDefault Generic Error used for most error responses - it returns a custom code and message depending on the reply context

swagger:response postUser2faDefault
*/
type PostUser2faDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Response `json:"body,omitempty"`
}

// NewPostUser2faDefault creates PostUser2faDefault with default headers values
func NewPostUser2faDefault(code int) *PostUser2faDefault {
	if code <= 0 {
		code = 500
	}

	return &PostUser2faDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the post user2fa default response
func (o *PostUser2faDefault) WithStatusCode(code int) *PostUser2faDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the post user2fa default response
func (o *PostUser2faDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the post user2fa default response
func (o *PostUser2faDefault) WithPayload(payload *models.Response) *PostUser2faDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post user2fa default response
func (o *PostUser2faDefault) SetPayload(payload *models.Response) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostUser2faDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
