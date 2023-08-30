package coreapi

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

type CreateTicketRequest struct {
	VerificationCode *string    `json:"verificationCode,omitempty"`
	Email            string     `json:"email"`
	Type             TicketType `json:"type"`
	Password         *string    `json:"password,omitempty"`
	TotpCode         *string    `json:"totpCode,omitempty"`
}
type Ticket struct {
	Token *string     `json:"token,omitempty"`
	Type  *TicketType `json:"type,omitempty"`
}
type AccountList struct {
	Data       []Account  `json:"data"`
	Pagination Pagination `json:"pagination"`
}
type Session struct {
	TokenType   string        `json:"tokenType"`
	TokenFormat string        `json:"tokenFormat"`
	ExpiredAt   int64         `json:"expiredAt"`
	CreatedAt   int64         `json:"createdAt"`
	Fa          []string      `json:"fa"`
	Status      SessionStatus `json:"status"`
	Account     Account       `json:"account"`
	Token       string        `json:"token"`
}
type CreateAccountRequest struct {
	VerificationCode *string `json:"verificationCode,omitempty"`
	Email            string  `json:"email"`
	Password         string  `json:"password"`
	Role             *Role   `json:"role,omitempty"`
}
type Pagination struct {
	Index int64 `json:"index"`
	Limit int64 `json:"limit"`
	Total int64 `json:"total"`
}
type Account struct {
	Role  Role   `json:"role"`
	Id    string `json:"id"`
	Email string `json:"email"`
}
type Totp struct {
	Url string `json:"url"`
}
type UpdatePasswordRequest struct {
	Password         *string `json:"password,omitempty"`
	NewPassword      string  `json:"newPassword"`
	Email            string  `json:"email"`
	VerificationCode *string `json:"verificationCode,omitempty"`
}
type CreateVerificationCodeRespones struct {
	Email   *string                 `json:"email,omitempty"`
	Purpose VerificationCodePurpose `json:"purpose"`
	Result  VerificationCodeResult  `json:"result"`
}
type CreateSessionRequest struct {
	Email            *string   `json:"email,omitempty"`
	Password         *string   `json:"password,omitempty"`
	TotpCode         *string   `json:"totpCode,omitempty"`
	VerificationCode *string   `json:"verificationCode,omitempty"`
	Tickets          *[]string `json:"tickets,omitempty"`
}
type PutTotpRequest struct {
	Url      *string   `json:"url,omitempty"`
	TotpCode *string   `json:"totpCode,omitempty"`
	Tickets  *[]string `json:"tickets,omitempty"`
}
type Service struct {
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Url         string      `json:"url"`
	Type        ServiceType `json:"type"`
	Id          string      `json:"id"`
	Name        string      `json:"name"`
}
type CreateServiceRequest struct {
	Description string      `json:"description"`
	Url         string      `json:"url"`
	Type        ServiceType `json:"type"`
	Name        string      `json:"name"`
	Title       string      `json:"title"`
}
type SessionVerificationRequest struct {
	Token string `json:"token"`
}
type ServiceList struct {
	Data       []Service  `json:"data"`
	Pagination Pagination `json:"pagination"`
}
type SessionVerification struct {
	Status SessionStatus `json:"status"`
}
type Error struct {
	StatusCode int64  `json:"statusCode"`
	Code       int64  `json:"code"`
	Message    string `json:"message"`
}
type CreateVerificationCodeRequest struct {
	Purpose VerificationCodePurpose `json:"purpose"`
	Email   *string                 `json:"email,omitempty"`
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

type TicketType string

const PASSWORD TicketType = "PASSWORD"
const EMAIL TicketType = "EMAIL"
const TOTP TicketType = "TOTP"

type ServiceType string

const IAAS ServiceType = "IAAS"
const PAAS ServiceType = "PAAS"
const SAAS ServiceType = "SAAS"

type SessionStatus string

const ACTIVED SessionStatus = "ACTIVED"
const TWO_FA SessionStatus = "TWO_FA"
const EXPIRED SessionStatus = "EXPIRED"
const DISACTIVED SessionStatus = "DISACTIVED"

type VerificationCodeResult string

const SUCCESS_CREATED VerificationCodeResult = "SUCCESS_CREATED"
const FREQUENT VerificationCodeResult = "FREQUENT"
const ACCOUNT_EXISTS VerificationCodeResult = "ACCOUNT_EXISTS"

type Ordering string

const ASCENDING Ordering = "ASCENDING"
const DESCENDING Ordering = "DESCENDING"

type AccountApiInterface interface {
	CreateAccount(gin_context *gin.Context, gin_body CreateAccountRequest)
	ListAccount(gin_context *gin.Context, ordering Ordering, index int64, limit int64)
	VerifySession(gin_context *gin.Context, gin_body SessionVerificationRequest)
	GetAccount(gin_context *gin.Context)
	GetTotp(gin_context *gin.Context)
	CreateTotp2FA(gin_context *gin.Context, gin_body PutTotpRequest)
	CreateSession(gin_context *gin.Context, gin_body CreateSessionRequest)
	UpdatePassword(gin_context *gin.Context, gin_body UpdatePasswordRequest)
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
func GetAccountBuilder(api AccountApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.GetAccount(gin_context)
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
func AccountApiInterfaceMounter(gin_router *gin.Engine, gwg_api_label AccountApiInterface) {
	gin_router.POST("/accounts", CreateAccountBuilder(gwg_api_label))
	gin_router.GET("/accounts", ListAccountBuilder(gwg_api_label))
	gin_router.GET("/accounts/session/verification", VerifySessionBuilder(gwg_api_label))
	gin_router.GET("/account", GetAccountBuilder(gwg_api_label))
	gin_router.GET("/account/totp", GetTotpBuilder(gwg_api_label))
	gin_router.PUT("/account/totp", CreateTotp2FABuilder(gwg_api_label))
	gin_router.POST("/account/session", CreateSessionBuilder(gwg_api_label))
	gin_router.PUT("/account/password", UpdatePasswordBuilder(gwg_api_label))
}

type ServicesApiInterface interface {
	CreateService(gin_context *gin.Context)
	ListServices(gin_context *gin.Context)
}

func CreateServiceBuilder(api ServicesApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.CreateService(gin_context)
	}
}
func ListServicesBuilder(api ServicesApiInterface) func(c *gin.Context) {
	return func(gin_context *gin.Context) {
		api.ListServices(gin_context)
	}
}
func ServicesApiInterfaceMounter(gin_router *gin.Engine, gwg_api_label ServicesApiInterface) {
	gin_router.POST("/services", CreateServiceBuilder(gwg_api_label))
	gin_router.GET("/services", ListServicesBuilder(gwg_api_label))
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
