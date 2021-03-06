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

// PassResetTemp pass reset temp
// swagger:model PassResetTemp

type PassResetTemp struct {

	// the jwt token accuired form the initial login
	// Required: true
	Jwt *string `json:"jwt"`

	// the new password for this user
	// Required: true
	PasswordNew *string `json:"passwordNew"`
}

/* polymorph PassResetTemp jwt false */

/* polymorph PassResetTemp passwordNew false */

// Validate validates this pass reset temp
func (m *PassResetTemp) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateJwt(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validatePasswordNew(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PassResetTemp) validateJwt(formats strfmt.Registry) error {

	if err := validate.Required("jwt", "body", m.Jwt); err != nil {
		return err
	}

	return nil
}

func (m *PassResetTemp) validatePasswordNew(formats strfmt.Registry) error {

	if err := validate.Required("passwordNew", "body", m.PasswordNew); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PassResetTemp) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PassResetTemp) UnmarshalBinary(b []byte) error {
	var res PassResetTemp
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
