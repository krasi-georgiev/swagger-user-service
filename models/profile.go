// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Profile profile
// swagger:model Profile
type Profile struct {

	// email
	// Required: true
	Email *string `json:"email"`

	// pass
	// Required: true
	Pass *string `json:"pass"`
}

// Validate validates this profile
func (m *Profile) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmail(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validatePass(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Profile) validateEmail(formats strfmt.Registry) error {

	if err := validate.Required("email", "body", m.Email); err != nil {
		return err
	}

	return nil
}

func (m *Profile) validatePass(formats strfmt.Registry) error {

	if err := validate.Required("pass", "body", m.Pass); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Profile) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Profile) UnmarshalBinary(b []byte) error {
	var res Profile
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
