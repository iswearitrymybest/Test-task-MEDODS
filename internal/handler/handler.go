package handler

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"log/slog"

	_ "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	psql "TestTaskMedods/internal/storage/postgresql"
	"TestTaskMedods/internal/token"
)

// GenerateTokenRequest - структура запроса для /token
type GenerateTokenRequest struct {
	UserID string `json:"user_id"`
}

// RefreshTokenRequest - структура запроса для /refresh
type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse - структура ответа для обоих эндпоинтов
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// getClientIP извлекает IP-адрес из запроса
func getClientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// mockSendEmailWarning просто логирует отправку почтового сообщения, не отправляя его
func mockSendEmailWarning(userEmail, oldIP, newIP string) {
	log.Printf("WARNING: IP changed for user %s from %s to %s. Email warning sent.", userEmail, oldIP, newIP)
}

// GenerateTokenHandler обрабатывает запрос на выдачу новой пары токенов по user_id.
func GenerateTokenHandler(storage *psql.Storage, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req GenerateTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		userID, err := uuid.Parse(req.UserID)
		if err != nil {
			http.Error(w, `{"error": "invalid user_id"}`, http.StatusBadRequest)
			return
		}

		clientIP := getClientIP(r)

		accessID, err := token.GenerateAccessID()
		if err != nil {
			logger.Error("could not generate access ID", "err", err)
			http.Error(w, `{"error": "could not generate access ID"}`, http.StatusInternalServerError)
			return
		}

		accessToken, err := token.GenerateAccessToken(userID, accessID, clientIP)
		if err != nil {
			logger.Error("could not generate access token", "err", err)
			http.Error(w, `{"error": "could not generate access token"}`, http.StatusInternalServerError)
			return
		}

		refreshToken, err := token.GenerateRefreshToken()
		if err != nil {
			logger.Error("could not generate refresh token", "err", err)
			http.Error(w, `{"error": "could not generate refresh token"}`, http.StatusInternalServerError)
			return
		}

		refreshHash, err := token.HashRefreshToken(refreshToken)
		if err != nil {
			logger.Error("could not hash refresh token", "err", err)
			http.Error(w, `{"error": "could not hash refresh token"}`, http.StatusInternalServerError)
			return
		}

		tokenPair := psql.TokenPair{
			UserID:        userID,
			RefreshHash:   refreshHash,
			AccessTokenID: accessID,
			CreatedAt:     time.Now(),
			ClientIP:      clientIP,
		}

		if err := storage.SaveTokenPair(tokenPair); err != nil {
			logger.Error("could not save token pair", "err", err)
			http.Error(w, `{"error": "could not save token pair"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}); err != nil {
			logger.Error("failed to encode response", "err", err)
		}
	}
}

// RefreshTokenHandler обрабатывает запрос на обновление токенов.
func RefreshTokenHandler(storage *psql.Storage, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		claims, err := token.ParseAccessToken(req.AccessToken)
		if err != nil {
			logger.Error("invalid access token", "err", err)
			http.Error(w, `{"error": "invalid access token"}`, http.StatusUnauthorized)
			return
		}

		accessID, ok := claims["access_id"].(string)
		if !ok {
			http.Error(w, `{"error": "invalid access token claims"}`, http.StatusUnauthorized)
			return
		}

		tp, err := storage.GetTokenPairByAccessID(accessID)
		if err != nil {
			logger.Error("token pair not found", "err", err)
			http.Error(w, `{"error": "token pair not found"}`, http.StatusUnauthorized)
			return
		}

		if err := token.CheckRefreshToken(tp.RefreshHash, req.RefreshToken); err != nil {
			logger.Error("invalid refresh token", "err", err)
			http.Error(w, `{"error": "invalid refresh token"}`, http.StatusUnauthorized)
			return
		}

		oldIP := tp.ClientIP
		newIP := getClientIP(r)

		if oldIP != newIP {
			mockSendEmailWarning("user@example.com", oldIP, newIP)
		}

		if err := storage.DeleteTokenPair(accessID); err != nil {
			logger.Error("could not delete old token pair", "err", err)
			http.Error(w, `{"error": "could not delete old token pair"}`, http.StatusInternalServerError)
			return
		}

		newAccessID, err := token.GenerateAccessID()
		if err != nil {
			logger.Error("could not generate access ID", "err", err)
			http.Error(w, `{"error": "could not generate access ID"}`, http.StatusInternalServerError)
			return
		}

		userID := tp.UserID
		newAccessToken, err := token.GenerateAccessToken(userID, newAccessID, newIP)
		if err != nil {
			logger.Error("could not generate access token", "err", err)
			http.Error(w, `{"error": "could not generate access token"}`, http.StatusInternalServerError)
			return
		}

		newRefreshToken, err := token.GenerateRefreshToken()
		if err != nil {
			logger.Error("could not generate refresh token", "err", err)
			http.Error(w, `{"error": "could not generate refresh token"}`, http.StatusInternalServerError)
			return
		}

		newRefreshHash, err := token.HashRefreshToken(newRefreshToken)
		if err != nil {
			logger.Error("could not hash refresh token", "err", err)
			http.Error(w, `{"error": "could not hash refresh token"}`, http.StatusInternalServerError)
			return
		}

		newTokenPair := psql.TokenPair{
			UserID:        userID,
			RefreshHash:   newRefreshHash,
			AccessTokenID: newAccessID,
			CreatedAt:     time.Now(),
			ClientIP:      newIP,
		}

		if err := storage.SaveTokenPair(newTokenPair); err != nil {
			logger.Error("could not save new token pair", "err", err)
			http.Error(w, `{"error": "could not save new token pair"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken,
		}); err != nil {
			logger.Error("failed to encode response", "err", err)
		}
	}
}
