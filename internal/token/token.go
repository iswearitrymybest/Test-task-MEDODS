package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

// expirationTime сделана в виде константы для упрощения смены времени жизни токена в дальнейшем.
const (
	expirationTime = 60
)

// GenerateAccessToken создает JWT Access токен.
// Expiration (exp) — 1 час.
func GenerateAccessToken(userID uuid.UUID, accessID, clientIP string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"user_id":   userID.String(),
		"exp":       time.Now().Add(time.Minute * expirationTime).Unix(),
		"access_id": accessID,
		"client_ip": clientIP,
	})
	return token.SignedString(jwtSecret)
}

// ParseAccessToken парсит Access токен и возвращает claims.
func ParseAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// GenerateRefreshToken создает случайную строку base64 длиной 32 байта.
// Это raw refresh token, который отдаём клиенту. Затем мы хэшируем его перед сохранением.
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashRefreshToken хэширует Refresh токен с помощью bcrypt.
func HashRefreshToken(refreshToken string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckRefreshToken сравнивает hash и предоставленный refreshToken.
func CheckRefreshToken(hash, refreshToken string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(refreshToken))
}

// GenerateAccessID генерирует UUID, который связывает Access и Refresh токены.
// Используется как уникальный ключ для идентификации пары.
func GenerateAccessID() (string, error) {
	uid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}

func SetSecret(secret string) {
	jwtSecret = []byte(secret)
}
