// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"

	strfmt "github.com/go-openapi/strfmt"
)

// NewListSnapshotsParams creates a new ListSnapshotsParams object
// no default values defined in spec.
func NewListSnapshotsParams() ListSnapshotsParams {

	return ListSnapshotsParams{}
}

// ListSnapshotsParams contains all the bound params for the list snapshots operation
// typically these are obtained from a http.Request
//
// swagger:parameters listSnapshots
type ListSnapshotsParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*The protected entity ID to retrieve info for
	  Required: true
	  In: path
	*/
	ProtectedEntityID string
	/*The service for the protected entity
	  Required: true
	  In: path
	*/
	Service string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewListSnapshotsParams() beforehand.
func (o *ListSnapshotsParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	rProtectedEntityID, rhkProtectedEntityID, _ := route.Params.GetOK("protectedEntityID")
	if err := o.bindProtectedEntityID(rProtectedEntityID, rhkProtectedEntityID, route.Formats); err != nil {
		res = append(res, err)
	}

	rService, rhkService, _ := route.Params.GetOK("service")
	if err := o.bindService(rService, rhkService, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindProtectedEntityID binds and validates parameter ProtectedEntityID from path.
func (o *ListSnapshotsParams) bindProtectedEntityID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route

	o.ProtectedEntityID = raw

	return nil
}

// bindService binds and validates parameter Service from path.
func (o *ListSnapshotsParams) bindService(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route

	o.Service = raw

	return nil
}