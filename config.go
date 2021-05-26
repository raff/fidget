package main

import (
	"bytes"
        "fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/hashicorp/hcl/v2/hclsimple"
)

type Config struct {
	Port    string `hcl:"port,optional"`
	Mitm    bool   `hcl:"mitm,optional"`
	Verbose bool   `hcl:"verbose,optional"`
	Logs    bool   `hcl:"logs,optional"`

	Locals map[string]string `hcl:"locals,optional"`

	Connects  []Connect  `hcl:"onConnect,block"`
	Requests  []Request  `hcl:"onRequest,block"`
	Responses []Response `hcl:"onResponse,block"`
}

type Connect struct {
	Conditions map[string]string `hcl:"conditions,optional"`
	Action     string            `hcl:"action"`
}

type Request struct {
	Conditions map[string]string `hcl:"conditions,optional"`
	ReqVals    *RequestConfig    `hcl:"request,block"`
	RespVals   *ResponseConfig   `hcl:"response,block"`
}

type RequestConfig struct {
	Query string `hcl:"query,optional"`

	SetHeaders Header   `hcl:"setHeaders,optional"`
	AddHeaders Header   `hcl:"addHeaders,optional"`
	DelHeaders []string `hcl:"delHeaders,optional"`
}

type ResponseConfig struct {
	Status *int   `hcl:"status,optional"`
	Body   string `hcl:"body,optional"`

	SetHeaders Header   `hcl:"setHeaders,optional"`
	AddHeaders Header   `hcl:"addHeaders,optional"`
	DelHeaders []string `hcl:"delHeaders,optional"`
}

type Response struct {
	Conditions map[string]string `hcl:"conditions,optional"`

	Status *int   `hcl:"status,optional"`
	Body   string `hcl:"body,optional"`

	SetHeaders Header   `hcl:"setHeaders,optional"`
	AddHeaders Header   `hcl:"addHeaders,optional"`
	DelHeaders []string `hcl:"delHeaders,optional"`
}

type Header map[string]string

type Context struct {
	Start time.Time
}

type HeaderUpdater interface {
	UpdateHeaders(ctx *goproxy.ProxyCtx, h http.Header)
}

func (r RequestConfig) UpdateHeaders(ctx *goproxy.ProxyCtx, h http.Header) {
	for _, k := range r.DelHeaders {
		ctx.Logf("  REQUEST HEADER DELETE %v", k)
		h.Del(k)
	}

	for k, v := range r.SetHeaders {
		ctx.Logf("  REQUEST HEADER SET %v: %v", k, v)
		h.Set(k, v)
	}

	for k, v := range r.AddHeaders {
		ctx.Logf("  REQUEST HEADER ADD %v: %v", k, v)
		h.Add(k, v)
	}
}

func (r ResponseConfig) UpdateHeaders(ctx *goproxy.ProxyCtx, h http.Header) {
	for _, k := range r.DelHeaders {
		ctx.Logf("  RESPONSE HEADER DELETE %v", k)
		h.Del(k)
	}

	for k, v := range r.SetHeaders {
		ctx.Logf("  RESPONSE HEADER SET %v: %v", k, v)
		h.Set(k, v)
	}

	for k, v := range r.AddHeaders {
		ctx.Logf("  RESPONSE HEADER ADD %v: %v", k, v)
		h.Add(k, v)
	}
}

func (r Response) UpdateHeaders(ctx *goproxy.ProxyCtx, h http.Header) {
	for _, k := range r.DelHeaders {
		ctx.Logf("  RESPONSE HEADER DELETE %v", k)
		h.Del(k)
	}

	for k, v := range r.SetHeaders {
		ctx.Logf("  RESPONSE HEADER SET %v: %v", k, v)
		h.Set(k, v)
	}

	for k, v := range r.AddHeaders {
		ctx.Logf("  RESPONSE HEADER ADD %v: %v", k, v)
		h.Add(k, v)
	}
}

func (c *Config) Load(cfile string) error {
	return hclsimple.DecodeFile(cfile, nil, c)
}

func (c *Config) NewProxy() (*goproxy.ProxyHttpServer, error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = c.Verbose || c.Logs

	if c.Logs {
		log.Println("[CONFIG] Log all requests/responses")

		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (ret *goproxy.ConnectAction, h string) {
				ctx.Logf("CONNECT %v", host)
				return nil, host // here we just want to log the connect
			})

		proxy.OnRequest().DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				ctx.Logf("REQUEST %v %v %v", r.Method, r.Proto, r.URL)
				for k, v := range r.Header {
					ctx.Logf(" %v: %v", k, v)
				}

				ctx.UserData = Context{Start: time.Now()}
				return r, nil
			})

		proxy.OnResponse().DoFunc(
			func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
				elapsed := ""
				if c, ok := ctx.UserData.(Context); ok {
					elapsed = fmt.Sprintf(" secs=%v", time.Since(c.Start).Truncate(time.Millisecond))
				}

				ctx.Logf("RESPONSE %v %v%v", r.Proto, r.Status, elapsed)
				for k, v := range r.Header {
					ctx.Logf(" %v: %v", k, v)
				}

				return r
			})
	}

	if c.Mitm {
		log.Println("[CONFIG] Enable MITM")
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	for i, r := range c.Connects {
		if c.Verbose {
			log.Println("[CONFIG] onConnect")
		}

		var conditions []goproxy.ReqCondition

		for ccond, cval := range r.Conditions {
			if cval == "" {
				log.Fatalf("[CONFIG] onConnect %v condition=%v - empty condition value\n", i, ccond)
			}

			if c.Verbose {
				log.Printf("           condition %v: %v", ccond, cval)
			}

			var negate bool

			if strings.HasPrefix(ccond, "!") {
				negate = true
				ccond = ccond[1:]
			}

			var cond goproxy.ReqCondition

			switch ccond {
			case "hostIs":
				cond = goproxy.DstHostIs(cval)

			case "hostMatches":
				cond = goproxy.ReqHostMatches(regexp.MustCompile(cval))

			case "urlIs":
				cond = goproxy.UrlIs(cval)

			case "urlHasPrefix":
				cond = goproxy.UrlHasPrefix(cval)

			case "urlMatches":
				cond = goproxy.UrlMatches(regexp.MustCompile(cval))

			case "methodIs":
				cond = reqMethodIs(cval)

			default:
				log.Fatalf("[CONFIG] onConnect %v - invalid condition %v\n", i, ccond)
			}

			if negate {
				cond = goproxy.Not(cond)
			}

			conditions = append(conditions, cond)
		}

		switch r.Action {
		case "accept", "reject", "mitm":
			if c.Verbose {
				log.Printf("           action: %v", r.Action)
			}

		default:
			log.Fatalf("[CONFIG] onConnect %v - invalid action %v\n", i, r.Action)
		}

		ccon := r

		proxy.OnRequest(conditions...).HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (ret *goproxy.ConnectAction, h string) {
				ctx.Logf("ONCONNECT %v", host)
				switch ccon.Action {
				case "reject":
					ctx.Logf("  REJECT")
					ret = goproxy.RejectConnect

				case "accept":
					ctx.Logf("  ACCEPT")
					ret = goproxy.OkConnect

				case "mitm":
					ctx.Logf("  ENABLE MITM")
					ret = goproxy.MitmConnect
				}

				return ret, host
			})
	}

	for i, r := range c.Requests {
		if c.Verbose {
			log.Println("[CONFIG] onRequest")
		}

		var conditions []goproxy.ReqCondition

		for ccond, cval := range r.Conditions {
			if cval == "" {
				log.Fatalf("[CONFIG] onRequest %v condition=%v - empty condition value\n", i, ccond)
			}

			if c.Verbose {
				log.Printf("           condition %v: %v", ccond, cval)
			}

			var negate bool

			if strings.HasPrefix(ccond, "!") {
				negate = true
				ccond = ccond[1:]
			}

			var cond goproxy.ReqCondition

			switch ccond {
			case "hostIs":
				cond = goproxy.ReqHostIs(cval)

			case "hostMatches":
				cond = goproxy.ReqHostMatches(regexp.MustCompile(cval))

			case "urlIs":
				cond = goproxy.UrlIs(cval)

			case "urlHasPrefix":
				cond = goproxy.UrlHasPrefix(cval)

			case "urlMatches":
				cond = goproxy.UrlMatches(regexp.MustCompile(cval))

			case "methodIs":
				cond = reqMethodIs(cval)

			default:
				log.Fatalf("[CONFIG] onRequest %v - invalid condition %v\n", i, ccond)
			}

			if negate {
				cond = goproxy.Not(cond)
			}

			conditions = append(conditions, cond)
		}

		creq := r

		proxy.OnRequest(conditions...).DoFunc(
			func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				ctx.Logf("ONREQUEST %v %v", req.Method, req.URL)

				if creq.ReqVals != nil {
					creq.ReqVals.UpdateHeaders(ctx, req.Header)

					if creq.ReqVals.Query != "" {
						ctx.Logf("  REQUEST QUERY %v", creq.ReqVals.Query)
						req.URL.RawQuery = url.QueryEscape(creq.ReqVals.Query)
					}
				}

				if creq.RespVals != nil {
					status := 200
					if creq.RespVals.Status != nil {
						ctx.Logf("  RESPONSE STATUS %v", *creq.RespVals.Status)
						status = *creq.RespVals.Status
					}

					res := goproxy.NewResponse(req, "", status, creq.RespVals.Body)

					if creq.RespVals != nil {
						creq.RespVals.UpdateHeaders(ctx, res.Header)
					}

					ctx.Logf("  RESPONSE BODY %q", creq.RespVals.Body)
					return req, res
				}

				return req, nil
			})
	}

	for i, r := range c.Responses {
		if c.Verbose {
			log.Println("[CONFIG] onResponse")
		}

		var conditions []goproxy.RespCondition

		for ccond, cval := range r.Conditions {
			if cval == "" {
				log.Fatalf("[CONFIG] onRequest %v condition=%v - empty condition value\n", i, ccond)
			}

			if c.Verbose {
				log.Printf("           condition %v: %v", ccond, cval)
			}

			var negate bool

			if strings.HasPrefix(ccond, "!") {
				negate = true
				ccond = ccond[1:]
			}

			var cond goproxy.RespCondition

			switch ccond {
			case "hostIs":
				cond = goproxy.DstHostIs(cval)

			case "hostMatches":
				cond = goproxy.ReqHostMatches(regexp.MustCompile(cval))

			case "urlIs":
				cond = goproxy.UrlIs(cval)

			case "urlHasPrefix":
				cond = goproxy.UrlHasPrefix(cval)

			case "urlMatches":
				cond = goproxy.UrlMatches(regexp.MustCompile(cval))

			case "methodIs":
				cond = reqMethodIs(cval)

			case "statusIs":
				status, _ := strconv.Atoi(cval)
				cond = goproxy.StatusCodeIs(status)

			case "contentTypeIs":
				cond = goproxy.ContentTypeIs(cval)

			case "hasHeader":
				cond = hasHeader(cval)

			default:
				log.Fatalf("[CONFIG] onResponse %v - invalid condition %v\n", i, ccond)
			}

			if negate {
				cond = notResp(cond)
			}

			conditions = append(conditions, cond)
		}

		cres := r

		proxy.OnResponse(conditions...).DoFunc(
			func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
				ctx.Logf("ONRESPONSE %v %v", resp.Request.Method, resp.Request.URL)

				if cres.Status != nil {
					ctx.Logf("  RESPONSE STATUS %v", *cres.Status)
					resp.StatusCode = *cres.Status
					resp.Status = http.StatusText(resp.StatusCode)
				}

				cres.UpdateHeaders(ctx, resp.Header)

				if cres.Body != "" {
					ctx.Logf("  RESPONSE BODY %q", cres.Body)
					buf := bytes.NewBufferString(cres.Body)
					resp.ContentLength = int64(buf.Len())
					resp.Body = ioutil.NopCloser(buf)
				}

				return resp
			})
	}

	return proxy, nil
}

func reqMethodIs(method string) goproxy.ReqConditionFunc {
	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		return req.Method == method
	}
}

func notResp(r goproxy.RespCondition) goproxy.RespConditionFunc {
	return func(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
		return !r.HandleResp(resp, ctx)
	}
}

func hasHeader(h string) goproxy.RespConditionFunc {
	return func(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
		_, ok := resp.Header[h]
		return ok
	}
}
