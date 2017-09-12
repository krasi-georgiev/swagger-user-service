package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"image/png"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	qr "github.com/qpliu/qrencode-go/qrencode"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/vanderbr/choicehealth_user-service/models"
	"github.com/vanderbr/choicehealth_user-service/restapi/operations"
	"golang.org/x/crypto/bcrypt"
)

func F2aDisable(params operations.DeleteUserIDF2aParams, principal interface{}) middleware.Responder {
	j, ok := principal.(*Jwt)
	if !ok {
		return operations.NewDeleteUserIDF2aDefault(0)
	}

	var password string
	err := db.QueryRow("SELECT password FROM public.user WHERE id=$1", j.Id_profile).Scan(&password)

	if err != nil {
		log.Println(err)
		return operations.NewDeleteUserIDF2aDefault(0)
	}
	// password ok so can disable IDF2a
	if bcrypt.CompareHashAndPassword([]byte(password), []byte(*params.Body.Password)) == nil {
		_, err = db.Exec("UPDATE public.user SET f2a=NULL WHERE id=$1 ;", params.ID)
		if err != nil {
			log.Println(err)
			return operations.NewDeleteUserIDF2aDefault(0)
		}
		return operations.NewDeleteUserIDF2aOK()

	}
	return operations.NewDeleteUserIDF2aUnauthorized()

}

func F2aGenerator(params operations.GetUserF2aParams) middleware.Responder {
	secret, err := genSecretKey()
	if err != nil {
		log.Println(err)
		return operations.NewGetUserF2aDefault(0)
	}

	if qr, err := barcodeImage("Choicehealth", []byte(secret)); err == nil {
		return operations.NewGetUserF2aOK().WithPayload(operations.GetUserF2aOKBody{Qr: swag.String(qr), Secret: swag.String(secret)})

	}

	log.Println(err)
	return operations.NewGetUserF2aDefault(0)
}

//F2aEnable Expects a valid F2a token to verify and enable on the account
func F2aEnable(params operations.PutUserIDF2aParams) middleware.Responder {
	// just check that the jwt token is valid
	if v, ok := params.HTTPRequest.Header["X-Jwt"]; ok {
		_, err := ParseJwt(strings.Join(v, ""))
		if err != nil {
			return operations.NewPutUserIDF2aUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("invalid login token")}))
		}
	} else {
		return operations.NewPutUserIDF2aUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("invalid login token")}))
	}

	// verify the code and if match save the master secret for the account
	code, _, err := getCurrentIDF2aCode(*params.Body.Secret)
	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDF2aDefault(0)
	}

	// code matches so can save the secret in the db
	if code == *params.Body.Code {
		_, err = db.Exec("UPDATE public.user SET f2a=$1,f2a_enforced=false WHERE id=$2 ;", params.Body.Secret, params.ID)
		if err != nil {
			log.Println(err)
			return operations.NewPutUserIDF2aDefault(0)
		}
		return operations.NewPutUserIDF2aOK().WithPayload((&models.Response{Code: swag.Int64(200), Message: swag.String("2 factor enabled. Please logout and login again.")}))
	}
	return operations.NewPutUserIDF2aUnauthorized().WithPayload((&models.Response{Code: swag.Int64(401), Message: swag.String("mismatched 2 factor code")}))

}

//F2aAuthenticate authenticate against the IDF2a
func F2aAuthenticate(params operations.PostUserF2aParams) middleware.Responder {
	var tt *Jwt
	if t, err := ParseJwt(*params.Body.Jwt); err != nil {
		log.Println(err)
		return operations.NewPostUserF2aUnauthorized().WithPayload(&models.Response{Code: swag.Int64(int64(err.Code())), Message: swag.String(err.Error())})
	} else {
		tt = t
	}

	var f2a string
	err := db.QueryRow("SELECT f2a FROM public.user WHERE id=$1", tt.Id_profile).Scan(&f2a)
	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDF2aDefault(0)
	}

	code, _, err := getCurrentIDF2aCode(f2a)
	if err != nil {
		log.Println(err)
		return operations.NewPutUserIDF2aDefault(0)
	}

	if code == *params.Body.F2a {

		// now generate a new jwt token without the IDF2a lock
		t := jwt.MapClaims{
			"exp":        time.Now().Add(time.Hour * 240).Unix(),
			"id_profile": strconv.Itoa(tt.Id_profile),
			// "user_type_id": strconv.Itoa(tt.User_type_id),
		}
		t["scope"], err = setScopes(tt.Id_profile)
		if err != nil {
			return operations.NewPutUserIDF2aDefault(0)
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, t)
		tt, err := token.SignedString(SignKey)
		if err != nil {
			return operations.NewPutUserIDF2aDefault(0)
		}
		return operations.NewPostUserF2aOK().WithPayload(&models.Jwt{Jwt: swag.String(tt)})
	}
	return operations.NewPostUserF2aUnauthorized().WithPayload(&models.Response{Code: swag.Int64(401), Message: swag.String("invalid IDF2a token")})

}

func genSecretKey() (string, error) {

	hmac_hash := sha256.New()

	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, getTs())
	if err != nil {
		return "", err
	}
	h := hmac.New(func() hash.Hash { return hmac_hash }, buf.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func getTs() int64 {
	un := float64(time.Now().UnixNano()) / float64(1000) / float64(30)
	return int64(math.Floor(un))
}

func getCurrentIDF2aCode(secretKey string) (string, int64, error) {
	now := time.Now().Unix()
	interval := 30
	t_chunk := (now / int64(interval))

	buf_in := bytes.Buffer{}
	err := binary.Write(&buf_in, binary.BigEndian, int64(t_chunk))
	if err != nil {
		return "", 0, err
	}

	h := hmac.New(func() hash.Hash { return sha1.New() }, bytes.NewBufferString(secretKey).Bytes())
	h.Reset()

	h.Write(buf_in.Bytes())
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xF
	code_sect := sum[offset : offset+4]

	var code int32
	buf_out := bytes.NewBuffer(code_sect)
	err = binary.Read(buf_out, binary.BigEndian, &code)
	if err != nil {
		return "", 0, err
	}

	code = code & 0x7FFFFFFF

	code = code % 1000000

	i := int64(interval)
	x := (((now + i) / i) * i) - now

	return fmt.Sprintf("%06d", code), x, nil
}

func barcodeImage(label string, secretkey []byte) (string, error) {
	issuer := "go-google-authenticator"

	otp_str := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, label, base32.StdEncoding.EncodeToString(secretkey), issuer)

	c, err := qr.Encode(otp_str, qr.ECLevelM)

	if err != nil {
		return "", err
	}

	var buf bytes.Buffer

	err = png.Encode(&buf, c.Image(8))

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
