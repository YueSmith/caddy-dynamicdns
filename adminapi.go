// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(adminAPI{})
}

// adminAPI exposes the dynamic_dns app on the Caddy admin API.
//
// It lives in the "admin.api" namespace, so Caddy registers its routes
// automatically whenever this package is compiled in; no configuration is
// required. The route exists even when the dynamic_dns app is not
// configured, in which case requests are answered with 503.
type adminAPI struct {
	app *App
	ctx caddy.Context
	log *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (adminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.dynamic_dns",
		New: func() caddy.Module { return new(adminAPI) },
	}
}

// Provision sets up the module and captures the dynamic_dns app, if one
// is configured.
func (a *adminAPI) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.log = ctx.Logger(a)

	// Use AppIfConfigured rather than App: this route is registered
	// whether or not the app is configured, and App would try to load an
	// app that isn't in the config, which would fail the whole config.
	app, err := ctx.AppIfConfigured("dynamic_dns")
	if err == nil {
		a.app = app.(*App)
	}

	return nil
}

// Routes returns the admin route for this app.
func (a *adminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/dynamic_dns/check",
			Handler: caddy.AdminHandlerFunc(a.handleCheck),
		},
	}
}

// handleCheck forces an immediate IP address check and DNS update, and
// reports the IP addresses found and the records that were written.
func (a *adminAPI) handleCheck(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed: %v", r.Method),
		}
	}
	if a.app == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Err:        fmt.Errorf("the dynamic_dns app is not configured"),
		}
	}

	result, err := a.app.checkIPAndUpdateDNS()
	if err != nil {
		// A check that was skipped because of the cooldown is a client-side
		// problem, not a failure: tell the client when it may try again.
		var cdErr cooldownError
		if errors.As(err, &cdErr) {
			seconds := int(cdErr.remaining.Seconds() + 0.999)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			return caddy.APIError{
				HTTPStatus: http.StatusTooManyRequests,
				Err:        err,
			}
		}
		return caddy.APIError{
			HTTPStatus: http.StatusBadGateway,
			Err:        err,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        err,
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Module      = (*adminAPI)(nil)
	_ caddy.Provisioner = (*adminAPI)(nil)
	_ caddy.AdminRouter = (*adminAPI)(nil)
)
