package cors

import (
	"strconv"
	"strings"

	"github.com/savsgio/atreugo/v11"
	"github.com/valyala/fasthttp"
)

const strHeaderDelim = ", "

// Config configuration.
type Config struct {
	// Specifies either the origins, which tells browsers to allow that origin
	// to access the resource; or else — for requests without credentials —
	// the "*" wildcard, to tell browsers to allow any origin to access the resource.
	AllowedOrigins []string

	// Specifies the method or methods allowed when accessing the resource.
	// This is used in response to a preflight request.
	// The conditions under which a request is preflighted are discussed above.
	AllowedMethods []string

	// This is used in response to a preflight request to indicate which HTTP headers
	// can be used when making the actual request.
	AllowedHeaders []string

	// Indicates whether or not the response to the request can be exposed when
	// the credentials flag is true. When used as part of a response to a preflight request,
	// this indicates whether or not the actual request can be made using credentials.
	// Note that simple GET requests are not preflighted, and so if a request is made
	// for a resource with credentials, if this header is not returned with the resource,
	// the response is ignored by the browser and not returned to web content.
	AllowCredentials bool

	// Indicates how long, in seconds, the results of a preflight request can be cached
	AllowMaxAge int

	// Header or headers to lets a server whitelist headers that browsers are allowed to access.
	ExposedHeaders []string
}

func isAllowedOrigin(allowed []string, origin string) bool {
	for _, v := range allowed {
		if v == origin || v == "*" {
			return true
		}
	}

	return false
}

// New returns the middleware with the configured properties
//
// IMPORTANT: always use as last middleware (`server.UseAfter(...)`).
func New(cfg Config) atreugo.Middleware {
	allowedHeaders := strings.Join(cfg.AllowedHeaders, strHeaderDelim)
	allowedMethods := strings.Join(cfg.AllowedMethods, strHeaderDelim)
	exposedHeaders := strings.Join(cfg.ExposedHeaders, strHeaderDelim)
	maxAge := strconv.Itoa(cfg.AllowMaxAge)

	return func(ctx *atreugo.RequestCtx) error {
		origin := string(ctx.Request.Header.Peek(fasthttp.HeaderOrigin))

		if !isAllowedOrigin(cfg.AllowedOrigins, origin) {
			return ctx.Next()
		}

		ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowOrigin, origin)

		if cfg.AllowCredentials {
			ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowCredentials, "true")
		}

		varyHeader := ctx.Response.Header.Peek(fasthttp.HeaderVary)
		if len(varyHeader) > 0 {
			varyHeader = append(varyHeader, strHeaderDelim...)
		}

		varyHeader = append(varyHeader, fasthttp.HeaderOrigin...)
		ctx.Response.Header.SetBytesV(fasthttp.HeaderVary, varyHeader)

		if len(cfg.ExposedHeaders) > 0 {
			ctx.Response.Header.Set(fasthttp.HeaderAccessControlExposeHeaders, exposedHeaders)
		}

		method := string(ctx.Method())
		if method != fasthttp.MethodOptions {
			return ctx.Next()
		}

		if len(cfg.AllowedHeaders) > 0 {
			ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowHeaders, allowedHeaders)
		}

		if len(cfg.AllowedMethods) > 0 {
			ctx.Response.Header.Set(fasthttp.HeaderAccessControlAllowMethods, allowedMethods)
		}

		if cfg.AllowMaxAge > 0 {
			ctx.Response.Header.Set(fasthttp.HeaderAccessControlMaxAge, maxAge)
		}

		return ctx.Next()
	}
}
