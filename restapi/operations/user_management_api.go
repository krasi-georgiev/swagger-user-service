// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"net/http"
	"strings"

	errors "github.com/go-openapi/errors"
	loads "github.com/go-openapi/loads"
	runtime "github.com/go-openapi/runtime"
	middleware "github.com/go-openapi/runtime/middleware"
	spec "github.com/go-openapi/spec"
	strfmt "github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/choicehealth/user-service/restapi/operations/users"
	"github.com/go-openapi/runtime/security"
)

// NewUserManagementAPI creates a new UserManagement instance
func NewUserManagementAPI(spec *loads.Document) *UserManagementAPI {
	return &UserManagementAPI{
		handlers:            make(map[string]map[string]http.Handler),
		formats:             strfmt.Default,
		defaultConsumes:     "application/json",
		defaultProduces:     "application/json",
		ServerShutdown:      func() {},
		spec:                spec,
		ServeError:          errors.ServeError,
		BasicAuthenticator:  security.BasicAuth,
		APIKeyAuthenticator: security.APIKeyAuth,
		BearerAuthenticator: security.BearerAuth,
		JSONConsumer:        runtime.JSONConsumer(),
		JSONProducer:        runtime.JSONProducer(),
		UsersPostCreateHandler: users.PostCreateHandlerFunc(func(params users.PostCreateParams, principal interface{}) middleware.Responder {
			return middleware.NotImplemented("operation UsersPostCreate has not yet been implemented")
		}),
		UsersPostLoginHandler: users.PostLoginHandlerFunc(func(params users.PostLoginParams) middleware.Responder {
			return middleware.NotImplemented("operation UsersPostLogin has not yet been implemented")
		}),
		UsersPostPasswordHandler: users.PostPasswordHandlerFunc(func(params users.PostPasswordParams, principal interface{}) middleware.Responder {
			return middleware.NotImplemented("operation UsersPostPassword has not yet been implemented")
		}),

		// Applies when the "x-token" header is set
		SwtAuthAuth: func(token string) (interface{}, error) {
			return nil, errors.NotImplemented("api key auth (swtAuth) x-token from header param [x-token] has not yet been implemented")
		},
	}
}

/*UserManagementAPI a service for user management. */
type UserManagementAPI struct {
	spec            *loads.Document
	context         *middleware.Context
	handlers        map[string]map[string]http.Handler
	formats         strfmt.Registry
	defaultConsumes string
	defaultProduces string
	Middleware      func(middleware.Builder) http.Handler

	// BasicAuthenticator generates a runtime.Authenticator from the supplied basic auth function.
	// It has a default implemention in the security package, however you can replace it for your particular usage.
	BasicAuthenticator func(security.UserPassAuthentication) runtime.Authenticator
	// APIKeyAuthenticator generates a runtime.Authenticator from the supplied token auth function.
	// It has a default implemention in the security package, however you can replace it for your particular usage.
	APIKeyAuthenticator func(string, string, security.TokenAuthentication) runtime.Authenticator
	// BearerAuthenticator generates a runtime.Authenticator from the supplied bearer token auth function.
	// It has a default implemention in the security package, however you can replace it for your particular usage.
	BearerAuthenticator func(string, security.ScopedTokenAuthentication) runtime.Authenticator

	// JSONConsumer registers a consumer for a "application/json" mime type
	JSONConsumer runtime.Consumer

	// JSONProducer registers a producer for a "application/json" mime type
	JSONProducer runtime.Producer

	// SwtAuthAuth registers a function that takes a token and returns a principal
	// it performs authentication based on an api key x-token provided in the header
	SwtAuthAuth func(string) (interface{}, error)

	// UsersPostCreateHandler sets the operation handler for the post create operation
	UsersPostCreateHandler users.PostCreateHandler
	// UsersPostLoginHandler sets the operation handler for the post login operation
	UsersPostLoginHandler users.PostLoginHandler
	// UsersPostPasswordHandler sets the operation handler for the post password operation
	UsersPostPasswordHandler users.PostPasswordHandler

	// ServeError is called when an error is received, there is a default handler
	// but you can set your own with this
	ServeError func(http.ResponseWriter, *http.Request, error)

	// ServerShutdown is called when the HTTP(S) server is shut down and done
	// handling all active connections and does not accept connections any more
	ServerShutdown func()

	// Custom command line argument groups with their descriptions
	CommandLineOptionsGroups []swag.CommandLineOptionsGroup

	// User defined logger function.
	Logger func(string, ...interface{})
}

// SetDefaultProduces sets the default produces media type
func (o *UserManagementAPI) SetDefaultProduces(mediaType string) {
	o.defaultProduces = mediaType
}

// SetDefaultConsumes returns the default consumes media type
func (o *UserManagementAPI) SetDefaultConsumes(mediaType string) {
	o.defaultConsumes = mediaType
}

// SetSpec sets a spec that will be served for the clients.
func (o *UserManagementAPI) SetSpec(spec *loads.Document) {
	o.spec = spec
}

// DefaultProduces returns the default produces media type
func (o *UserManagementAPI) DefaultProduces() string {
	return o.defaultProduces
}

// DefaultConsumes returns the default consumes media type
func (o *UserManagementAPI) DefaultConsumes() string {
	return o.defaultConsumes
}

// Formats returns the registered string formats
func (o *UserManagementAPI) Formats() strfmt.Registry {
	return o.formats
}

// RegisterFormat registers a custom format validator
func (o *UserManagementAPI) RegisterFormat(name string, format strfmt.Format, validator strfmt.Validator) {
	o.formats.Add(name, format, validator)
}

// Validate validates the registrations in the UserManagementAPI
func (o *UserManagementAPI) Validate() error {
	var unregistered []string

	if o.JSONConsumer == nil {
		unregistered = append(unregistered, "JSONConsumer")
	}

	if o.JSONProducer == nil {
		unregistered = append(unregistered, "JSONProducer")
	}

	if o.SwtAuthAuth == nil {
		unregistered = append(unregistered, "XTokenAuth")
	}

	if o.UsersPostCreateHandler == nil {
		unregistered = append(unregistered, "users.PostCreateHandler")
	}

	if o.UsersPostLoginHandler == nil {
		unregistered = append(unregistered, "users.PostLoginHandler")
	}

	if o.UsersPostPasswordHandler == nil {
		unregistered = append(unregistered, "users.PostPasswordHandler")
	}

	if len(unregistered) > 0 {
		return fmt.Errorf("missing registration: %s", strings.Join(unregistered, ", "))
	}

	return nil
}

// ServeErrorFor gets a error handler for a given operation id
func (o *UserManagementAPI) ServeErrorFor(operationID string) func(http.ResponseWriter, *http.Request, error) {
	return o.ServeError
}

// AuthenticatorsFor gets the authenticators for the specified security schemes
func (o *UserManagementAPI) AuthenticatorsFor(schemes map[string]spec.SecurityScheme) map[string]runtime.Authenticator {

	result := make(map[string]runtime.Authenticator)
	for name, scheme := range schemes {
		switch name {

		case "swtAuth":

			result[name] = o.APIKeyAuthenticator(scheme.Name, scheme.In, o.SwtAuthAuth)

		}
	}
	return result

}

// ConsumersFor gets the consumers for the specified media types
func (o *UserManagementAPI) ConsumersFor(mediaTypes []string) map[string]runtime.Consumer {

	result := make(map[string]runtime.Consumer)
	for _, mt := range mediaTypes {
		switch mt {

		case "application/json":
			result["application/json"] = o.JSONConsumer

		}
	}
	return result

}

// ProducersFor gets the producers for the specified media types
func (o *UserManagementAPI) ProducersFor(mediaTypes []string) map[string]runtime.Producer {

	result := make(map[string]runtime.Producer)
	for _, mt := range mediaTypes {
		switch mt {

		case "application/json":
			result["application/json"] = o.JSONProducer

		}
	}
	return result

}

// HandlerFor gets a http.Handler for the provided operation method and path
func (o *UserManagementAPI) HandlerFor(method, path string) (http.Handler, bool) {
	if o.handlers == nil {
		return nil, false
	}
	um := strings.ToUpper(method)
	if _, ok := o.handlers[um]; !ok {
		return nil, false
	}
	if path == "/" {
		path = ""
	}
	h, ok := o.handlers[um][path]
	return h, ok
}

// Context returns the middleware context for the user management API
func (o *UserManagementAPI) Context() *middleware.Context {
	if o.context == nil {
		o.context = middleware.NewRoutableContext(o.spec, o, nil)
	}

	return o.context
}

func (o *UserManagementAPI) initHandlerCache() {
	o.Context() // don't care about the result, just that the initialization happened

	if o.handlers == nil {
		o.handlers = make(map[string]map[string]http.Handler)
	}

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/create"] = users.NewPostCreate(o.context, o.UsersPostCreateHandler)

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/login"] = users.NewPostLogin(o.context, o.UsersPostLoginHandler)

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/password"] = users.NewPostPassword(o.context, o.UsersPostPasswordHandler)

}

// Serve creates a http handler to serve the API over HTTP
// can be used directly in http.ListenAndServe(":8000", api.Serve(nil))
func (o *UserManagementAPI) Serve(builder middleware.Builder) http.Handler {
	o.Init()

	if o.Middleware != nil {
		return o.Middleware(builder)
	}
	return o.context.APIHandler(builder)
}

// Init allows you to just initialize the handler cache, you can then recompose the middelware as you see fit
func (o *UserManagementAPI) Init() {
	if len(o.handlers) == 0 {
		o.initHandlerCache()
	}
}
