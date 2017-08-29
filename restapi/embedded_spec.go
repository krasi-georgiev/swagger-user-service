// Code generated by go-swagger; DO NOT EDIT.

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

// SwaggerJSON embedded version of the swagger document used at generation time
var SwaggerJSON json.RawMessage

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "consumes": [
    "application/json"
  ],
  "produces": [
    "application/json"
  ],
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "title": "User Management",
    "version": "0.0.1"
  },
  "basePath": "/v1/",
  "paths": {
    "/user": {
      "get": {
        "summary": "generates a list of users",
        "parameters": [
          {
            "type": "integer",
            "description": "The number of items to skip before starting to collect the result set",
            "name": "offset",
            "in": "query"
          },
          {
            "type": "integer",
            "description": "The numbers of items to return",
            "name": "limit",
            "in": "query"
          }
        ],
        "responses": {
          "200": {
            "description": "full user list",
            "schema": {
              "type": "array",
              "items": {
                "properties": {
                  "created": {
                    "type": "string"
                  },
                  "f2a": {
                    "type": "integer"
                  },
                  "id": {
                    "type": "integer"
                  },
                  "username": {
                    "type": "string"
                  }
                }
              }
            }
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      }
    },
    "/user/2fa": {
      "get": {
        "summary": "generate qr base64 encoded image and master code for the user to scan with the google authenticator and add it to the phone app",
        "responses": {
          "200": {
            "description": "A 2fa object.",
            "schema": {
              "properties": {
                "qr": {
                  "type": "string"
                },
                "secret": {
                  "type": "string"
                }
              }
            }
          },
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      },
      "put": {
        "summary": "enables 2fa on an account",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/F2aEnable"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "2fa enabled."
          },
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      },
      "post": {
        "summary": "used when the account is with 2 factor authentication enabled. use the login endpoint first to get the initial jwt token and than use this endpoint to get the second jwt token after providing a valid google authenticator code",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/F2aAuth"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "the new jwt token that can be used for all endpoints.",
            "schema": {
              "$ref": "#/definitions/Jwt"
            }
          },
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      },
      "delete": {
        "summary": "disable 2 factor authenticaiton for an account",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/F2aDisable"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "2fa disabled."
          },
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      }
    },
    "/user/login": {
      "post": {
        "summary": "generates a swt token to use for authentication",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/Login"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "A jwt token to use for authentication.",
            "schema": {
              "$ref": "#/definitions/Jwt"
            }
          },
          "201": {
            "description": "Password change is required, hit the password reset endpoint with the generated jwt token",
            "schema": {
              "$ref": "#/definitions/Jwt"
            }
          },
          "206": {
            "description": "Account is with 2 factor authenticaiton so use the 2 factor endpoint to generate the final the jwt token.",
            "schema": {
              "$ref": "#/definitions/Jwt"
            }
          },
          "404": {
            "$ref": "#/responses/NotFoundError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      }
    },
    "/user/management": {
      "post": {
        "summary": "creates a new user",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/Profile"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "An user id of the created user.",
            "schema": {
              "type": "object",
              "properties": {
                "id_profile": {
                  "type": "integer"
                }
              }
            }
          },
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "404": {
            "$ref": "#/responses/NotFoundError"
          },
          "409": {
            "$ref": "#/responses/UserExistsError"
          },
          "426": {
            "$ref": "#/responses/ExpiredTokenError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      },
      "delete": {
        "summary": "deletes a user from the db",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "type": "object",
              "required": [
                "id_profile"
              ],
              "properties": {
                "id_profile": {
                  "type": "integer"
                }
              }
            }
          }
        ],
        "responses": {
          "200": {
            "description": "user deleted"
          },
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "404": {
            "$ref": "#/responses/NotFoundError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      }
    },
    "/user/password": {
      "put": {
        "summary": "resets an user password using a temporary password provided by an admin, once reset you can login as normal using the new password",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/PassResetTemp"
            }
          }
        ],
        "responses": {
          "200": {},
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      },
      "post": {
        "summary": "reset an user password, when old password is not provided the user will be required to change its password upon next login using a temporary password provided by an admin",
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/PassReset"
            }
          }
        ],
        "responses": {
          "200": {},
          "401": {
            "$ref": "#/responses/UnauthorizedError"
          },
          "404": {
            "$ref": "#/responses/NotFoundError"
          },
          "default": {
            "$ref": "#/responses/DefaultError"
          }
        }
      }
    }
  },
  "definitions": {
    "F2aAuth": {
      "type": "object",
      "required": [
        "jwt",
        "f2a"
      ],
      "properties": {
        "f2a": {
          "description": "the  2 factor time code accuired from the google authenticator app",
          "type": "string"
        },
        "jwt": {
          "description": "the jwt token accuired form the initial login",
          "type": "string"
        }
      }
    },
    "F2aDisable": {
      "type": "object",
      "required": [
        "password"
      ],
      "properties": {
        "password": {
          "type": "string"
        }
      }
    },
    "F2aEnable": {
      "type": "object",
      "required": [
        "code",
        "secret"
      ],
      "properties": {
        "code": {
          "description": "the 2 factor code generted by the android app after scanning the barcode",
          "type": "string"
        },
        "secret": {
          "description": "the master password which will be used to for decoding",
          "type": "string"
        }
      }
    },
    "Jwt": {
      "type": "object",
      "required": [
        "jwt"
      ],
      "properties": {
        "jwt": {
          "type": "string"
        }
      }
    },
    "Login": {
      "type": "object",
      "required": [
        "username",
        "password"
      ],
      "properties": {
        "password": {
          "type": "string"
        },
        "username": {
          "type": "string"
        }
      },
      "example": {
        "password": "password",
        "username": "admin@mail.com"
      }
    },
    "PassReset": {
      "type": "object",
      "required": [
        "id_profile",
        "password_new"
      ],
      "properties": {
        "id_profile": {
          "type": "integer"
        },
        "password_new": {
          "type": "string"
        },
        "password_old": {
          "type": "string"
        }
      }
    },
    "PassResetTemp": {
      "type": "object",
      "required": [
        "jwt",
        "passwordNew"
      ],
      "properties": {
        "jwt": {
          "description": "the jwt token accuired form the initial login",
          "type": "string"
        },
        "passwordNew": {
          "description": "the new password for this user",
          "type": "string"
        }
      }
    },
    "Profile": {
      "type": "object",
      "required": [
        "username",
        "password",
        "active",
        "role",
        "tenant_id"
      ],
      "properties": {
        "active": {
          "type": "boolean"
        },
        "email": {
          "type": "string"
        },
        "password": {
          "type": "string"
        },
        "role": {
          "items": {
            "type": "integer"
          }
        },
        "tenant_id": {
          "type": "integer",
          "default": 1,
          "enum": [
            1
          ]
        },
        "username": {
          "type": "string"
        }
      },
      "example": {
        "active": true,
        "email": "admin@mail.com",
        "password": "password",
        "role": [
          1,
          2
        ],
        "tenant_id": 1,
        "username": "username"
      }
    },
    "Response": {
      "type": "object",
      "required": [
        "code",
        "message"
      ],
      "properties": {
        "code": {
          "type": "integer"
        },
        "message": {
          "type": "string"
        }
      },
      "example": {
        "code": "500",
        "message": "Server error"
      }
    }
  },
  "responses": {
    "DefaultError": {
      "description": "Unexpected error",
      "schema": {
        "$ref": "#/definitions/Response"
      }
    },
    "ExpiredTokenError": {
      "description": "SWT key has expired, request a new one",
      "schema": {
        "$ref": "#/definitions/Response"
      }
    },
    "NotFoundError": {
      "description": "Resource not found",
      "schema": {
        "$ref": "#/definitions/Response"
      }
    },
    "UnauthorizedError": {
      "description": "Authentication is missing or invalid",
      "schema": {
        "$ref": "#/definitions/Response"
      }
    },
    "UserExistsError": {
      "description": "Username already taken",
      "schema": {
        "$ref": "#/definitions/Response"
      }
    }
  },
  "securityDefinitions": {
    "jwt": {
      "type": "apiKey",
      "name": "x-jwt",
      "in": "header"
    }
  },
  "security": [
    {
      "jwt": []
    }
  ]
}`))
}
