// SPDX-License-Identifier: MPL-2.0

package handler

import (
	"log/slog"
	"net/http"
	"shaper/server/core"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func ListConnections(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}
		result, err := core.ListConnections(app, c.Request().Context())
		if err != nil {
			c.Logger().Error("error listing connections:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: err.Error()}, "  ")
		}
		return c.JSONPretty(http.StatusOK, result, "  ")
	}
}

func CreateConnection(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}

		var request struct {
			Name       string `json:"name"`
			Host       string `json:"host"`
			Port       int    `json:"port"`
			Username   string `json:"username"`
			Password   string `json:"password"`
			UseTLS     bool   `json:"useTls"`
			SkipVerify bool   `json:"skipVerify"`
		}
		if err := c.Bind(&request); err != nil {
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: "Invalid request"}, "  ")
		}

		id, err := core.CreateConnection(app, c.Request().Context(),
			request.Name, request.Host, request.Port,
			request.Username, request.Password,
			request.UseTLS, request.SkipVerify)
		if err != nil {
			c.Logger().Error("error creating connection:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: err.Error()}, "  ")
		}

		return c.JSONPretty(http.StatusCreated, struct {
			ID string `json:"id"`
		}{ID: id}, "  ")
	}
}

func UpdateConnection(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}

		var request struct {
			Name       string `json:"name"`
			Host       string `json:"host"`
			Port       int    `json:"port"`
			Username   string `json:"username"`
			Password   string `json:"password"`
			UseTLS     bool   `json:"useTls"`
			SkipVerify bool   `json:"skipVerify"`
		}
		if err := c.Bind(&request); err != nil {
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: "Invalid request"}, "  ")
		}

		err := core.UpdateConnection(app, c.Request().Context(), c.Param("id"),
			request.Name, request.Host, request.Port,
			request.Username, request.Password,
			request.UseTLS, request.SkipVerify)
		if err != nil {
			c.Logger().Error("error updating connection:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: err.Error()}, "  ")
		}

		return c.JSONPretty(http.StatusOK, struct {
			OK bool `json:"ok"`
		}{OK: true}, "  ")
	}
}

func DeleteConnection(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}

		err := core.DeleteConnection(app, c.Request().Context(), c.Param("id"))
		if err != nil {
			c.Logger().Error("error deleting connection:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: err.Error()}, "  ")
		}

		return c.JSONPretty(http.StatusOK, struct {
			Deleted bool `json:"deleted"`
		}{Deleted: true}, "  ")
	}
}

func TestConnection(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}

		err := core.TestConnection(app, c.Request().Context(), c.Param("id"))
		if err != nil {
			c.Logger().Error("error testing connection:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error   string `json:"error"`
				Success bool   `json:"success"`
			}{Error: err.Error(), Success: false}, "  ")
		}

		return c.JSONPretty(http.StatusOK, struct {
			Success bool `json:"success"`
		}{Success: true}, "  ")
	}
}

func OAuthStart(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}

		oauthURL, sessionUUID, authURL, err := core.OAuthStartFlow(app, c.Request().Context(), c.Param("id"))
		if err != nil {
			c.Logger().Error("error starting OAuth flow:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: err.Error()}, "  ")
		}

		return c.JSONPretty(http.StatusOK, struct {
			OAuthURL    string `json:"oauthUrl"`
			SessionUUID string `json:"sessionUuid"`
			AuthURL     string `json:"authUrl"`
		}{
			OAuthURL:    oauthURL,
			SessionUUID: sessionUUID,
			AuthURL:     authURL,
		}, "  ")
	}
}

func OAuthComplete(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}

		var request struct {
			OAuthURL    string `json:"oauthUrl"`
			SessionUUID string `json:"sessionUuid"`
		}
		if err := c.Bind(&request); err != nil {
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: "Invalid request"}, "  ")
		}

		err := core.OAuthFinalize(app, c.Request().Context(), c.Param("id"), request.OAuthURL, request.SessionUUID)
		if err != nil {
			c.Logger().Error("error completing OAuth flow:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error   string `json:"error"`
				Success bool   `json:"success"`
			}{Error: err.Error(), Success: false}, "  ")
		}

		return c.JSONPretty(http.StatusOK, struct {
			Success bool `json:"success"`
		}{Success: true}, "  ")
	}
}

func SaveDashboardConnection(app *core.App) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		if _, hasId := claims["dashboardId"]; hasId {
			return c.JSONPretty(http.StatusUnauthorized, struct {
				Error string `json:"error"`
			}{Error: "Unauthorized"}, "  ")
		}
		if app.NoEdit {
			return c.JSONPretty(http.StatusForbidden, struct {
				Error string `json:"error"`
			}{Error: "Editing is disabled"}, "  ")
		}

		var request struct {
			ConnectionID *string `json:"connectionId"`
		}
		if err := c.Bind(&request); err != nil {
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: "Invalid request"}, "  ")
		}

		err := core.SaveDashboardConnection(app, c.Request().Context(), c.Param("id"), request.ConnectionID)
		if err != nil {
			c.Logger().Error("error saving dashboard connection:", slog.Any("error", err))
			return c.JSONPretty(http.StatusBadRequest, struct {
				Error string `json:"error"`
			}{Error: err.Error()}, "  ")
		}

		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	}
}
