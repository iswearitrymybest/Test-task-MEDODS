// **Задание:**
// Написать часть сервиса аутентификации.

// Два REST маршрута:
// - Первый маршрут выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса
// - Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов

// **Требования:**
// Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.
// Refresh токен тип произвольный, формат передачи base64, хранится в базе исключительно в виде bcrypt хеша, должен быть защищен от изменения на стороне клиента и попыток повторного использования.
// Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.
// Payload токенов должен содержать сведения об ip адресе клиента, которому он был выдан. В случае, если ip адрес изменился, при рефреш операции нужно послать email warning на почту юзера (для упрощения можно использовать моковые данные).

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"

	"TestTaskMedods/internal/config"
	"TestTaskMedods/internal/handler"
	mwLogger "TestTaskMedods/internal/lib/logger"
	sl "TestTaskMedods/internal/lib/slog"
	psql "TestTaskMedods/internal/storage/postgresql"
	"TestTaskMedods/internal/token"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

// Main - запуск нашего REST сервера
// Для проверки можно отправить GET запрос на эндпоинт /token с "user_id": "00000000-0000-0000-0000-000000000001" или любым другим UUID для user'а
func main() {
	cfg := config.MustLoad()
	token.SetSecret(cfg.JwtSecret)

	log := setupLogger(cfg.Env)
	log.Info(
		"starting project",
		slog.String("env", cfg.Env),
	)
	log.Debug("debug messages are enabled")

	storage, err := psql.New(cfg.StoragePath)
	if err != nil {
		log.Error("failed to init storage", sl.Err(err))
		os.Exit(1)
	}

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(mwLogger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	router.Post("/token", handler.GenerateTokenHandler(storage, log))
	router.Post("/refresh", handler.RefreshTokenHandler(storage, log))

	log.Info("starting server", slog.String("address", cfg.Address))

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("failed to start server", sl.Err(err))
		}
	}()

	log.Info("server started")

	<-done
	log.Info("stopping server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("failed to stop server", sl.Err(err))

		return
	}

	log.Info("server stopped")
}

// setupLogger устанавливает логгер в зависимости от окружения, пользуемся slog из стандартного пакета golang
func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	default:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
