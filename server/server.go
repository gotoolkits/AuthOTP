package server

import (
	"fmt"
	"github.com/gotoolkits/authOtp/auth"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
	"net/http"
	"sync"
	"time"
)

var (
	sHost       = "8018"
	svrstus     SvrStatus
	info        SysInfo
	authMux     *sync.Mutex
	otpMux      *sync.Mutex
	registerMux *sync.Mutex
)

type AuthCode struct {
	Skey string `json:"skey" xml:"skey" form:"skey" query:"skey"`
}

type Authencator struct {
	Skey string `json:"skey" xml:"skey" form:"skey" query:"skey"`
	Otp  string `json:"otp" xml:"otp" form:"otp" query:"otp"`
}

type SvrStatus struct {
	Stime         string `json:"start_time"`
	RegisterCount Count  `json:"register_count"`
	OtpCount      Count  `json:"otp_count"`
	AuthCount     Count  `json:"auth_count"`
}

type Count struct {
	Success int `json:"success"`
	Failed  int `json:"failed"`
}

type SysInfo struct {
	SysName string `json:"AppName"`
	Version string `json:"Version"`
	Author  string `json:"Author"`
}

func init() {
	svrstus = SvrStatus{
		RegisterCount: Count{},
		OtpCount:      Count{},
		AuthCount:     Count{},
	}

	info = SysInfo{
		SysName: "AuthOtp",
		Version: "V0.1.1",
		Author:  "gotoolkits",
	}

	authMux = new(sync.Mutex)
	otpMux = new(sync.Mutex)
	registerMux = new(sync.Mutex)

}

func ServerRun() {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.POST},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	e.GET("/register", FnGenSecKey)
	e.POST("/otp", FnGetOTP)
	e.POST("/auth", FnAuthencator)

	//self running status for monitor
	e.GET("/ping", FnHealthCheck)
	e.GET("/status", FnStatus)
	e.GET("/info", FnInfo)

	log.Println("⇨ http server starting on ", ":"+sHost)

	svrstus.Stime = time.Now().Format("2006-01-02 15:04:05")

	e.Logger.Fatal(e.Start(":" + sHost))
}

//Generate a Private key (Base64 format)
func FnGenSecKey(c echo.Context) error {
	secKey, err := auth.GenSecretKey("sha1")
	if err != nil {
		secCount("register", true)
		return c.String(http.StatusBadGateway, "Error happened!")
	}
	secCount("register", false)
	return c.String(http.StatusOK, secKey)
}

//Generate a OTP code by private key (seed)
func FnGetOTP(c echo.Context) error {
	code := new(AuthCode)

	if err := c.Bind(code); err != nil {
		log.Println(err)
		secCount("otp", true)
		return c.String(http.StatusBadRequest, "Post body parse failed.")
	}

	if code.Skey == "" || len(code.Skey) != 64 {
		secCount("otp", true)
		return c.String(http.StatusBadRequest, "Bad args.")
	}

	t := int(time.Now().Unix() / 30)
	otp := auth.ComputeCode(code.Skey, int64(t))

	strOTP := fmt.Sprintf("%.6d", otp)

	secCount("otp", false)
	return c.JSONPretty(http.StatusOK, strOTP, " ")
}

// To Authencate OTP code
func FnAuthencator(c echo.Context) error {
	athor := new(Authencator)
	if err := c.Bind(athor); err != nil {
		log.Println(err)
		secCount("auth", true)
		return c.String(http.StatusBadRequest, "Post body parse failed.")
	}

	if athor.Skey == "" || athor.Otp == "" {
		secCount("auth", true)
		return c.String(http.StatusBadRequest, "Must args can't null.")
	}

	if len(athor.Skey) != 64 || len(athor.Otp) != 6 {
		secCount("auth", true)
		return c.String(http.StatusBadRequest, "bad args.")
	}

	otpc := auth.InitOTPConfig(athor.Skey)
	ok, err := otpc.Authenticate(athor.Otp)
	if err != nil {
		log.Println(err)
		secCount("auth", true)
		return c.String(http.StatusExpectationFailed, "Error happened!")
	}

	if ok {
		secCount("auth", false)
	} else {
		secCount("auth", true)
	}

	return c.JSONPretty(http.StatusOK, ok, " ")
}

func FnHealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "PONG")
}

func FnStatus(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, svrstus, " ")
}

func FnInfo(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, info, " ")
}

func secCount(t string, err bool) {

	if t == "register" {
		if err {
			registerMux.Lock()
			svrstus.RegisterCount.Failed++
			registerMux.Unlock()
		} else {
			registerMux.Lock()
			svrstus.RegisterCount.Success++
			registerMux.Unlock()
		}
	} else if t == "otp" {
		if err {
			otpMux.Lock()
			svrstus.OtpCount.Failed++
			otpMux.Unlock()
		} else {
			otpMux.Lock()
			svrstus.OtpCount.Success++
			otpMux.Unlock()
		}
	} else if t == "auth" {
		if err {
			authMux.Lock()
			svrstus.AuthCount.Failed++
			authMux.Unlock()
		} else {
			authMux.Lock()
			svrstus.AuthCount.Success++
			authMux.Unlock()
		}
	} else {
		return
	}

}
