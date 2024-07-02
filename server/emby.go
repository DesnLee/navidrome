package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/deluan/rest"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func embyAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Emby-Token")

		if token == "" {
			token = r.URL.Query().Get("X-Emby-Token")
		}

		if token == "" {
			log.Error(r, "missing token")
			responseWithString(w, http.StatusUnauthorized, "missing token")
			return
		} else if token != conf.Server.Token {
			log.Error(r, "invalid token")
			responseWithString(w, http.StatusUnauthorized, "invalid token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func responseWithString(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(fmt.Sprintf("Navidrome: %s", message)))
}

func parseBody(r *http.Request, data interface{}) error {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(data); err != nil {
		log.Error(r.Context(), "parsing request body", err)
		return err
	}
	return nil
}

func parseUrlParams(r *http.Request) map[string]string {
	m := make(map[string]string)
	ctx := chi.RouteContext(r.Context())
	for i, key := range ctx.URLParams.Keys {
		value := ctx.URLParams.Values[i]
		m[key] = value
	}
	return m
}

func isSqlite3Error(err error, code error) bool {
	var e sqlite3.Error
	if errors.As(err, &e) {
		return errors.Is(e.ExtendedCode, code)
	}
	return false
}

func toEmbyUser(u model.User) map[string]any {
	return map[string]any{
		"Id":       u.ID,
		"Name":     u.Name,
		"ServerId": conf.Server.ServerId,
		"Policy":   map[string]any{},
	}
}

func createEmbyUser(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data := make(map[string]string)
		if err := parseBody(r, &data); err != nil {
			responseWithString(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// 校验参数
		username := data["Name"]
		password := data["Password"]
		if username == "" || password == "" {
			responseWithString(w, http.StatusBadRequest, "missing username or password")
			return
		}

		log.Info(r.Context(), "Creating user", "user", username)

		now := time.Now()
		caser := cases.Title(language.Und)
		initialUser := model.User{
			ID:          uuid.NewString(),
			UserName:    username,
			Name:        caser.String(username),
			Email:       "",
			NewPassword: password,
			IsAdmin:     false,
			LastLoginAt: &now,
		}

		err := ds.User(r.Context()).Put(&initialUser)
		if err != nil {
			if isSqlite3Error(err, sqlite3.ErrConstraintUnique) {
				log.Error(r.Context(), "User already exists", "user", initialUser, err)
				responseWithString(w, http.StatusNotAcceptable, "user already exists.")
				return
			}

			log.Error(r.Context(), "Could not create user", "user", initialUser, err)
			responseWithString(w, http.StatusBadRequest, "could not create user.")
			return
		}

		_ = rest.RespondWithJSON(w, http.StatusOK, toEmbyUser(initialUser))
	}
}

func loginEmbyUser(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data := make(map[string]string)
		if err := parseBody(r, &data); err != nil {
			responseWithString(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// 校验参数
		username := data["Username"]
		password := data["Pw"]
		if username == "" || password == "" {
			responseWithString(w, http.StatusBadRequest, "missing username or password")
			return
		}

		log.Info(r.Context(), "Login emby user", "user", username)

		u, err := ds.User(r.Context()).FindByUsernameWithPassword(username)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				log.Error(r.Context(), "User not found", "user", username, err)
				responseWithString(w, http.StatusNotFound, "user not found.")
				return
			}

			log.Error(r.Context(), "Could not get user", "user", username, err)
			responseWithString(w, http.StatusInternalServerError, "could not get user.")
			return
		}

		if u.Password != password {
			log.Error(r.Context(), "Invalid password", "user", username)
			responseWithString(w, http.StatusUnauthorized, "invalid password.")
			return
		}

		responseWithString(w, http.StatusOK, "ok")
	}
}

func getEmbyUsers(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info(r.Context(), "Get all emby users")

		us, err := ds.User(r.Context()).GetAll()
		if err != nil {
			log.Error(r.Context(), "Could not get users", err)
			responseWithString(w, http.StatusInternalServerError, "could not get users.")
			return
		}

		newList := make([]map[string]any, len(us))
		for i, u := range us {
			newList[i] = toEmbyUser(u)
		}

		_ = rest.RespondWithJSON(w, http.StatusOK, newList)
	}
}

func setUserPolicy(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		urlParams := parseUrlParams(r)
		id := urlParams["id"]

		if id == "" {
			responseWithString(w, http.StatusBadRequest, "missing id")
			return
		}

		// 检查请求字段是否存在 IsDisabled，如果存在按照对应操作进行操作
		data := struct {
			IsDisabled *bool `json:"IsDisabled"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Error(r.Context(), "parsing request body", err)
			responseWithString(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// 不存在直接返回 ok
		if data.IsDisabled == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		log.Info(r.Context(), "Setting policy", "id", id, "IsDisabled", data.IsDisabled)

		// 获取用户
		user, err := ds.User(r.Context()).Get(id)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				log.Error(r.Context(), "User not found", "id", id, err)
				responseWithString(w, http.StatusNotFound, "user not found.")
				return
			}

			log.Error(r.Context(), "Could not get user", "id", id, err)
			responseWithString(w, http.StatusInternalServerError, "could not get user.")
			return
		}
		user, err = ds.User(r.Context()).FindByUsernameWithPassword(user.UserName)
		if err != nil {
			log.Error(r.Context(), "Could not get user", "id", id, err)
			responseWithString(w, http.StatusInternalServerError, "could not get user.")
			return
		}

		// 如果为 true 则是冻结用户，如果为 false 则是解冻用户
		// 具体操作为修改密码，添加固定的 navidrome 前缀
		needPut := false
		if *data.IsDisabled && !strings.HasPrefix(user.Password, conf.Server.FreezePrefix) {
			user.NewPassword = conf.Server.FreezePrefix + user.Password
			needPut = true
		} else if !*data.IsDisabled && strings.HasPrefix(user.Password, conf.Server.FreezePrefix) {
			user.NewPassword = strings.TrimPrefix(user.Password, conf.Server.FreezePrefix)
			needPut = true
		}

		if needPut {
			err = ds.User(r.Context()).Put(user)
			if err != nil {
				log.Error(r.Context(), "Could not update user", "user", user, err)
				responseWithString(w, http.StatusInternalServerError, "could not update user.")
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func setUserPassword(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		urlParams := parseUrlParams(r)
		id := urlParams["id"]

		// 校验 ID
		if id == "" {
			responseWithString(w, http.StatusBadRequest, "missing id")
			return
		}

		// 校验 body
		data := make(map[string]any)
		if err := parseBody(r, &data); err != nil {
			responseWithString(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// 校验参数
		newPw := data["NewPw"].(string)
		if newPw == "" {
			responseWithString(w, http.StatusBadRequest, "missing new password")
			return
		}

		log.Info(r.Context(), "Setting password", "id", id)

		// 获取用户
		user, err := ds.User(r.Context()).Get(id)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				log.Error(r.Context(), "User not found", "id", id, err)
				responseWithString(w, http.StatusNotFound, "user not found.")
				return
			}
			log.Error(r.Context(), "Could not get user", "id", id, err)
			responseWithString(w, http.StatusInternalServerError, "could not get user.")
			return
		}

		// 更新密码
		user.NewPassword = newPw
		err = ds.User(r.Context()).Put(user)
		if err != nil {
			log.Error(r.Context(), "Could not update user", "user", user, err)
			responseWithString(w, http.StatusInternalServerError, "could not update user.")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteEmbyUser(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		urlParams := parseUrlParams(r)
		id := urlParams["id"]

		// 校验 ID
		if id == "" {
			responseWithString(w, http.StatusBadRequest, "missing id")
			return
		}

		log.Info(r.Context(), "Deleting user", "id", id)

		// 删除用户
		err := ds.User(r.Context()).DeleteUser(id)
		if err != nil {
			if errors.Is(err, rest.ErrNotFound) {
				log.Error(r.Context(), "User not found", "id", id, err)
				responseWithString(w, http.StatusNotFound, "user not found.")
				return
			}
			log.Error(r.Context(), "Could not delete user", "id", id, err)
			responseWithString(w, http.StatusInternalServerError, "could not delete user.")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func getEmbySessions(w http.ResponseWriter, r *http.Request) {
	log.Info(r.Context(), "Get all emby sessions")
	// 返回空列表
	_ = rest.RespondWithJSON(w, http.StatusOK, []map[string]any{})
}
