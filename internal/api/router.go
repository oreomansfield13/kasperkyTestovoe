package api

import (
	"log"
	"net/http"
	"time"
)

func loggignMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func NewRouter(handler *ThreatHandler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /info", handler.Create)
	mux.HandleFunc("GET /info/{md5}", handler.GetByMD5)
	mux.HandleFunc("PUT /info/{md5}", handler.Update)

	return loggignMiddleware(mux)
}
