package coreapi

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

type PutTotpRequest struct {
	Url      string   `json:"url"`
	TotpCode string   `json:"totpCode"`
	Tickets  []string `json:"tickets"`
}
type CredentialCreationResponse struct {
	RawId      string           `json:"rawId"`
	Response   WebAuthnResponse `json:"response"`
	Transports []string         `json:"transports"`
	Name       string           `json:"name"`
	Os         string           `json:"os"`
	Type       string           `json:"type"`
	Id         string           `json:"id"`
}
type CreateSessionRequest struct {
	Tickets          *[]string `json:"tickets,omitempty"`
	Email            *string   `json:"email,omitempty"`
	Password         *string   `json:"password,omitempty"`
	TotpCode         *string   `json:"totpCode,omitempty"`
	VerificationCode *string   `json:"verificationCode,omitempty"`
}
type Account struct {
	Role    Role   `json:"role"`
	HasTotp bool   `json:"hasTotp"`
	Id      string `json:"id"`
	Email   string `json:"email"`
}
type SessionVerification struct {
	Status SessionStatus `json:"status"`
}
type CreateTicketChallenge struct {
	Email string `json:"email"`
}
type WebAuthn struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"`
	Os        string `json:"os"`
}
type Ticket struct {
	Token string     `json:"token"`
	Type  TicketType `json:"type"`
}
type Service struct {
	Id          string      `json:"id"`
	Name        string      `json:"name"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Url         string      `json:"url"`
	Type        ServiceType `json:"type"`
}
type WebAuthnResponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}
type CreateAccountRequest struct {
	VerificationCode *string `json:"verificationCode,omitempty"`
	Email            string  `json:"email"`
	Password         string  `json:"password"`
	Role             *Role   `json:"role,omitempty"`
}
type Authentication struct {
	Factors []string `json:"factors"`
}
type PublicKey struct {
	PubKeyCredParams       []PubKeyCredParam      `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Rp                     Rp                     `json:"rp"`
	User                   WebauthnUser           `json:"user"`
	Challenge              string                 `json:"challenge"`
}
type WebauthnUser struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}
type CreateVerificationCodeRequest struct {
	Email   *string                 `json:"email,omitempty"`
	Purpose VerificationCodePurpose `json:"purpose"`
}
type Pagination struct {
	Total int64 `json:"total"`
	Index int64 `json:"index"`
	Limit int64 `json:"limit"`
}
type CreateServiceRequest struct {
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Url         string      `json:"url"`
	Type        ServiceType `json:"type"`
	Name        string      `json:"name"`
}
type Session struct {
	CreatedAt   int64         `json:"createdAt"`
	Fa          []string      `json:"fa"`
	Status      SessionStatus `json:"status"`
	Account     Account       `json:"account"`
	Token       string        `json:"token"`
	TokenType   string        `json:"tokenType"`
	TokenFormat string        `json:"tokenFormat"`
	ExpiredAt   int64         `json:"expiredAt"`
}
type WebAuthnSession struct {
	Id        string    `json:"id"`
	PublicKey PublicKey `json:"publicKey"`
}
type Rp struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}
type SessionVerificationRequest struct {
	Token string `json:"token"`
}
type Totp struct {
	Url string `json:"url"`
}
type ServiceList struct {
	Data       []Service  `json:"data"`
	Pagination Pagination `json:"pagination"`
}
type AuthenticatorSelection struct {
	RequireResidentKey bool   `json:"requireResidentKey"`
	UserVerification   string `json:"userVerification"`
}
type Error struct {
	Code       int64  `json:"code"`
	Message    string `json:"message"`
	StatusCode int64  `json:"statusCode"`
}
type UpdatePasswordRequest struct {
	NewPassword      string  `json:"newPassword"`
	Email            string  `json:"email"`
	VerificationCode *string `json:"verificationCode,omitempty"`
	Password         *string `json:"password,omitempty"`
}
type AccountList struct {
	Data       []Account  `json:"data"`
	Pagination Pagination `json:"pagination"`
}
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}
type CreateVerificationCodeRespones struct {
	Email   *string                 `json:"email,omitempty"`
	Purpose VerificationCodePurpose `json:"purpose"`
	Result  VerificationCodeResult  `json:"result"`
}
type CreateTicketRequest struct {
	Email            string     `json:"email"`
	Type             TicketType `json:"type"`
	Password         *string    `json:"password,omitempty"`
	TotpCode         *string    `json:"totpCode,omitempty"`
	VerificationCode *string    `json:"verificationCode,omitempty"`
}
type VerificationCodePurpose string

const CREATE_ACCOUNT VerificationCodePurpose = "CREATE_ACCOUNT"
const SET_PASSWORD VerificationCodePurpose = "SET_PASSWORD"
const SIGNIN VerificationCodePurpose = "SIGNIN"
const CREATE_2FA VerificationCodePurpose = "CREATE_2FA"
const TICKET VerificationCodePurpose = "TICKET"

type Role string

const ROOT Role = "ROOT"
const ADMIN Role = "ADMIN"
const USER Role = "USER"

type SessionStatus string

const ACTIVED SessionStatus = "ACTIVED"
const TWO_FA SessionStatus = "TWO_FA"
const EXPIRED SessionStatus = "EXPIRED"
const DISACTIVED SessionStatus = "DISACTIVED"

type TicketType string

const PASSWORD TicketType = "PASSWORD"
const EMAIL TicketType = "EMAIL"
const TOTP TicketType = "TOTP"
const WEBAUTHN TicketType = "WEBAUTHN"

type Ordering string

const ASCENDING Ordering = "ASCENDING"
const DESCENDING Ordering = "DESCENDING"

type VerificationCodeResult string

const SUCCESS_CREATED VerificationCodeResult = "SUCCESS_CREATED"
const FREQUENT VerificationCodeResult = "FREQUENT"
const ACCOUNT_EXISTS VerificationCodeResult = "ACCOUNT_EXISTS"

type ServiceType string

const IAAS ServiceType = "IAAS"
const PAAS ServiceType = "PAAS"
const SAAS ServiceType = "SAAS"

type AccountApiInterface interface {
	GetAuthentication(gin_context *gin.Context, email string)
	CreateWebauthn(gin_context *gin.Context, id string)
	GetTotp(gin_context *gin.Context)
	CreateTotp2FA(gin_context *gin.Context, gin_body PutTotpRequest)
	DeleteTotp(gin_context *gin.Context)
	CreateSession(gin_context *gin.Context, gin_body CreateSessionRequest)
	GetAccount(gin_context *gin.Context)
	DeleteWebAuthn(gin_context *gin.Context, id string)
	UpdatePassword(gin_context *gin.Context, gin_body UpdatePasswordRequest)
	CreateAccount(gin_context *gin.Context, gin_body CreateAccountRequest)
	ListAccount(gin_context *gin.Context, ordering Ordering, index int64, limit int64)
	VerifySession(gin_context *gin.Context, gin_body SessionVerificationRequest)
	CreateWebAuthnChallenge(gin_context *gin.Context)
	CreateWebauthnTickets(gin_context *gin.Context, id string)
	ListWebAuthn(gin_context *gin.Context)
	CreateWebauthnTicketChallenge(gin_context *gin.Context, gin_body CreateTicketChallenge)
}

func GetAuthenticationBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		email := gin_context.Query("email")
		api.GetAuthentication(gin_context, email)
	}
}
func CreateWebauthnBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		id := gin_context.Param("id")
		api.CreateWebauthn(gin_context, id)
	}
}
func GetTotpBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.GetTotp(gin_context)
	}
}
func CreateTotp2FABuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var putTotpRequest PutTotpRequest
		if err := gin_context.ShouldBindJSON(&putTotpRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.CreateTotp2FA(gin_context, putTotpRequest)
	}
}
func DeleteTotpBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.DeleteTotp(gin_context)
	}
}
func CreateSessionBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var createSessionRequest CreateSessionRequest
		if err := gin_context.ShouldBindJSON(&createSessionRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.CreateSession(gin_context, createSessionRequest)
	}
}
func GetAccountBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.GetAccount(gin_context)
	}
}
func DeleteWebAuthnBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		id := gin_context.Param("id")
		api.DeleteWebAuthn(gin_context, id)
	}
}
func UpdatePasswordBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var updatePasswordRequest UpdatePasswordRequest
		if err := gin_context.ShouldBindJSON(&updatePasswordRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.UpdatePassword(gin_context, updatePasswordRequest)
	}
}
func CreateAccountBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var createAccountRequest CreateAccountRequest
		if err := gin_context.ShouldBindJSON(&createAccountRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.CreateAccount(gin_context, createAccountRequest)
	}
}
func ListAccountBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		ordering := gin_context.Query("ordering")
		index := gin_context.Query("index")
		limit := gin_context.Query("limit")
		api.ListAccount(gin_context, Ordering(ordering), stringToInt64(index), stringToInt64(limit))
	}
}
func VerifySessionBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var sessionVerificationRequest SessionVerificationRequest
		if err := gin_context.ShouldBindJSON(&sessionVerificationRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.VerifySession(gin_context, sessionVerificationRequest)
	}
}
func CreateWebAuthnChallengeBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.CreateWebAuthnChallenge(gin_context)
	}
}
func CreateWebauthnTicketsBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		id := gin_context.Param("id")
		api.CreateWebauthnTickets(gin_context, id)
	}
}
func ListWebAuthnBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.ListWebAuthn(gin_context)
	}
}
func CreateWebauthnTicketChallengeBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var createTicketChallenge CreateTicketChallenge
		if err := gin_context.ShouldBindJSON(&createTicketChallenge); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.CreateWebauthnTicketChallenge(gin_context, createTicketChallenge)
	}
}
func AccountApiInterfaceMounter(gin_router *gin.Engine, gwg_api_label AccountApiInterface) {
	gin_router.GET("/account/authentication", GetAuthenticationBuilder(gwg_api_label))
	gin_router.POST("/account/webauthn/sessions/:id", CreateWebauthnBuilder(gwg_api_label))
	gin_router.GET("/account/totp", GetTotpBuilder(gwg_api_label))
	gin_router.PUT("/account/totp", CreateTotp2FABuilder(gwg_api_label))
	gin_router.DELETE("/account/totp", DeleteTotpBuilder(gwg_api_label))
	gin_router.POST("/account/session", CreateSessionBuilder(gwg_api_label))
	gin_router.GET("/account", GetAccountBuilder(gwg_api_label))
	gin_router.DELETE("/account/webauthn/:id", DeleteWebAuthnBuilder(gwg_api_label))
	gin_router.PUT("/account/password", UpdatePasswordBuilder(gwg_api_label))
	gin_router.POST("/accounts", CreateAccountBuilder(gwg_api_label))
	gin_router.GET("/accounts", ListAccountBuilder(gwg_api_label))
	gin_router.GET("/accounts/session/verification", VerifySessionBuilder(gwg_api_label))
	gin_router.POST("/account/webauthn/sessions/challenge", CreateWebAuthnChallengeBuilder(gwg_api_label))
	gin_router.POST("/account/webauthn/sessions/tickets/:id", CreateWebauthnTicketsBuilder(gwg_api_label))
	gin_router.GET("/account/webauthn", ListWebAuthnBuilder(gwg_api_label))
	gin_router.POST("/account/webauthn/sessions/tickets/challenge", CreateWebauthnTicketChallengeBuilder(gwg_api_label))
}

type ServicesApiInterface interface {
	ListServices(gin_context *gin.Context)
	CreateService(gin_context *gin.Context)
}

func ListServicesBuilder(api ServicesApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.ListServices(gin_context)
	}
}
func CreateServiceBuilder(api ServicesApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.CreateService(gin_context)
	}
}
func ServicesApiInterfaceMounter(gin_router *gin.Engine, gwg_api_label ServicesApiInterface) {
	gin_router.GET("/services", ListServicesBuilder(gwg_api_label))
	gin_router.POST("/services", CreateServiceBuilder(gwg_api_label))
}

type VerificationApiInterface interface {
	CreateVerificationCode(gin_context *gin.Context, gin_body CreateVerificationCodeRequest)
}

func CreateVerificationCodeBuilder(api VerificationApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var createVerificationCodeRequest CreateVerificationCodeRequest
		if err := gin_context.ShouldBindJSON(&createVerificationCodeRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.CreateVerificationCode(gin_context, createVerificationCodeRequest)
	}
}
func VerificationApiInterfaceMounter(gin_router *gin.Engine, gwg_api_label VerificationApiInterface) {
	gin_router.POST("/verification/code", CreateVerificationCodeBuilder(gwg_api_label))
}

type TicketApiInterface interface {
	CreateTicket(gin_context *gin.Context, gin_body CreateTicketRequest)
}

func CreateTicketBuilder(api TicketApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		var createTicketRequest CreateTicketRequest
		if err := gin_context.ShouldBindJSON(&createTicketRequest); err != nil {
			gin_context.JSON(400, gin.H{})
			return
		}
		api.CreateTicket(gin_context, createTicketRequest)
	}
}
func TicketApiInterfaceMounter(gin_router *gin.Engine, gwg_api_label TicketApiInterface) {
	gin_router.POST("/tickets", CreateTicketBuilder(gwg_api_label))
}
func stringToInt32(s string) int32 {
	if value, err := strconv.ParseInt(s, 10, 32); err == nil {
		return int32(value)
	}
	return 0
}
func stringToInt64(s string) int64 {
	if value, err := strconv.ParseInt(s, 10, 64); err == nil {
		return value
	}
	return 0
}
func stringToFloat32(s string) float32 {
	if value, err := strconv.ParseFloat(s, 32); err == nil {
		return float32(value)
	}
	return 0
}
func stringToFloat64(s string) float64 {
	if value, err := strconv.ParseFloat(s, 64); err == nil {
		return value
	}
	return 0
}
