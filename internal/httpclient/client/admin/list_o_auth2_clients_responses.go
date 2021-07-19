// Code generated by go-swagger; DO NOT EDIT.

package admin

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/ory/hydra/internal/httpclient/models"
)

// ListOAuth2ClientsReader is a Reader for the ListOAuth2Clients structure.
type ListOAuth2ClientsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListOAuth2ClientsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListOAuth2ClientsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewListOAuth2ClientsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewListOAuth2ClientsOK creates a ListOAuth2ClientsOK with default headers values
func NewListOAuth2ClientsOK() *ListOAuth2ClientsOK {
	return &ListOAuth2ClientsOK{}
}

/*ListOAuth2ClientsOK handles this case with default header values.

A list of clients.
*/
type ListOAuth2ClientsOK struct {
	Payload []*models.OAuth2Client
}

func (o *ListOAuth2ClientsOK) Error() string {
	return fmt.Sprintf("[GET /clients][%d] listOAuth2ClientsOK  %+v", 200, o.Payload)
}

func (o *ListOAuth2ClientsOK) GetPayload() []*models.OAuth2Client {
	return o.Payload
}

func (o *ListOAuth2ClientsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListOAuth2ClientsInternalServerError creates a ListOAuth2ClientsInternalServerError with default headers values
func NewListOAuth2ClientsInternalServerError() *ListOAuth2ClientsInternalServerError {
	return &ListOAuth2ClientsInternalServerError{}
}

/*ListOAuth2ClientsInternalServerError handles this case with default header values.

jsonError
*/
type ListOAuth2ClientsInternalServerError struct {
	Payload *models.JSONError
}

func (o *ListOAuth2ClientsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /clients][%d] listOAuth2ClientsInternalServerError  %+v", 500, o.Payload)
}

func (o *ListOAuth2ClientsInternalServerError) GetPayload() *models.JSONError {
	return o.Payload
}

func (o *ListOAuth2ClientsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.JSONError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
