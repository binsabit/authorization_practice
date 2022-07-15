package api

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	data "github.com/binsabit/authorization_practice/internal/data/models"
	_ "github.com/lib/pq"
)

type config struct {
	port int
	db   struct {
		port         int
		host         string
		name         string
		password     string
		user         string
		maxOpenConns int
		maxIdleConns int
		maxIdleTime  string
	}
}

type application struct {
	logger *log.Logger
	config config
	models data.Models
}

func configure() config {
	return config{
		port: 4000,
		db: struct {
			port         int
			host         string
			name         string
			password     string
			user         string
			maxOpenConns int
			maxIdleConns int
			maxIdleTime  string
		}{
			port:         5432,
			host:         "localhost",
			name:         "auth",
			password:     "admin",
			user:         "postgres",
			maxOpenConns: 25,
			maxIdleConns: 25,
			maxIdleTime:  "15m",
		},
	}
}

func StartServer() {
	config := configure()

	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime)

	db, err := openDB(config)
	if err != nil {
		logger.Fatal(err)
	}

	defer db.Close()
	app := &application{
		logger: logger,
		config: config,
		models: data.NewModels(db),
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.port),
		Handler:      app.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logger.Printf("starting server on %s", srv.Addr)

	err = srv.ListenAndServe()
	logger.Fatal(err)
}

func openDB(cfg config) (*sql.DB, error) {
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", cfg.db.host, cfg.db.port, cfg.db.user, cfg.db.password, cfg.db.name))
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(cfg.db.maxOpenConns)

	db.SetMaxIdleConns(cfg.db.maxIdleConns)

	duration, err := time.ParseDuration(cfg.db.maxIdleTime)
	if err != nil {
		return nil, err
	}

	db.SetConnMaxIdleTime(duration)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}

	return db, nil
}
