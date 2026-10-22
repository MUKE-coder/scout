package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"

	"github.com/MUKE-coder/scout"
)

const shutdownTimeout = 10 * time.Second

// dashboardURL turns a listen address into a browsable dashboard URL.
func dashboardURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port) + scout.UIPath + "/"
}

func runServe(cmd *cobra.Command, addr, db string) error {
	level, _ := cmd.Flags().GetString("log-level")
	format, _ := cmd.Flags().GetString("log-format")
	log, err := scout.NewLogger(cmd.ErrOrStderr(), level, format)
	if err != nil {
		return err
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	explicit, _ := cmd.Flags().GetString("config")
	cfg, err := scout.LoadConfig(scout.FindConfig(explicit), os.Getenv)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("db") || cfg.DBPath == "" {
		cfg.DBPath = db
	}
	s, err := scout.New(cfg)
	if err != nil {
		return err
	}
	s.Register(router)

	srv := &http.Server{Addr: addr, Handler: router, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("scout serving", "addr", addr, "ui", dashboardURL(addr), "db", db)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
		close(errc)
	}()

	select {
	case err := <-errc:
		_ = s.Close(shutdownTimeout)
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = srv.Shutdown(shutCtx)
	if cerr := s.Close(shutdownTimeout); err == nil {
		err = cerr
	}
	return err
}
