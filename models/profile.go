// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

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

	// password
	// Required: true
	Password *string `json:"password"`

	// tenant id
	TenantID *string `json:"tenant_id,omitempty"`

	// user type id
	UserTypeID *string `json:"user_type_id,omitempty"`
}

// Validate validates this profile
func (m *Profile) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmail(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validatePassword(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validateTenantID(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validateUserTypeID(formats); err != nil {
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

func (m *Profile) validatePassword(formats strfmt.Registry) error {

	if err := validate.Required("password", "body", m.Password); err != nil {
		return err
	}

	return nil
}

var profileTypeTenantIDPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["1"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		profileTypeTenantIDPropEnum = append(profileTypeTenantIDPropEnum, v)
	}
}

const (
	// ProfileTenantIDNr1 captures enum value "1"
	ProfileTenantIDNr1 string = "1"
)

// prop value enum
func (m *Profile) validateTenantIDEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, profileTypeTenantIDPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Profile) validateTenantID(formats strfmt.Registry) error {

	if swag.IsZero(m.TenantID) { // not required
		return nil
	}

	// value enum
	if err := m.validateTenantIDEnum("tenant_id", "body", *m.TenantID); err != nil {
		return err
	}

	return nil
}

var profileTypeUserTypeIDPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["1","2"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		profileTypeUserTypeIDPropEnum = append(profileTypeUserTypeIDPropEnum, v)
	}
}

const (
	// ProfileUserTypeIDNr1 captures enum value "1"
	ProfileUserTypeIDNr1 string = "1"
	// ProfileUserTypeIDNr2 captures enum value "2"
	ProfileUserTypeIDNr2 string = "2"
)

// prop value enum
func (m *Profile) validateUserTypeIDEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, profileTypeUserTypeIDPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Profile) validateUserTypeID(formats strfmt.Registry) error {

	if swag.IsZero(m.UserTypeID) { // not required
		return nil
	}

	// value enum
	if err := m.validateUserTypeIDEnum("user_type_id", "body", *m.UserTypeID); err != nil {
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
