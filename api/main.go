package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// Entry — структура заметки
type Entry struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Created   int64  `json:"created"`
	FetchedAt int64  `json:"fetched_at,omitempty"`
	SourceURL string `json:"source_url,omitempty"`
}

// простой in-memory стор
var (
	store   = make(map[int64]*Entry)
	storeMu sync.RWMutex
	nextID  int64 = 1
)

// writeJSON ответ в формате JSON
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// CRUD хендлеры
func handleList(w http.ResponseWriter, r *http.Request) {
	storeMu.RLock()
	defer storeMu.RUnlock()
	out := make([]*Entry, 0, len(store))
	for _, e := range store {
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}

// Create создает новую заметку
func handleCreate(w http.ResponseWriter, r *http.Request) {
	var in Entry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	storeMu.Lock()
	in.ID = nextID
	nextID++
	in.Created = time.Now().Unix()
	store[in.ID] = &in
	storeMu.Unlock()
	writeJSON(w, http.StatusCreated, in)
}

// Get возвращает заметку по ID
func handleGet(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	storeMu.RLock()
	e, ok := store[id]
	storeMu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// Update обновляет заметку по ID
func handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var in Entry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	storeMu.Lock()
	e, ok := store[id]
	if !ok {
		storeMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if in.Title != "" {
		e.Title = in.Title
	}
	if in.Content != "" {
		e.Content = in.Content
	}
	storeMu.Unlock()
	writeJSON(w, http.StatusOK, e)
}

// Delete удаляет заметку по ID
func handleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	storeMu.Lock()
	_, ok := store[id]
	if ok {
		delete(store, id)
	}
	storeMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseIDFromPath извлекает ID из пути /entries/{id}
func parseIDFromPath(p string) (int64, error) {
	const prefix = "/entries/"
	if !strings.HasPrefix(p, prefix) {
		return 0, errors.New("bad path")
	}
	idStr := p[len(prefix):]
	if idStr == "" {
		return 0, errors.New("missing id")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// httpClientViaSocks5 создает HTTP клиент, который ходит через SOCKS5 прокси (tor)
func httpClientViaSocks5(socksAddr string, timeout time.Duration) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	// обёртка для DialContext
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}
	transport := &http.Transport{
		DialContext:           dialContext,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   8,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	return client, nil
}

// fetchRequest структура запроса на /fetch
type fetchRequest struct {
	URL string `json:"url"`
}

// handleFetch обрабатывает запросы на /fetch, делает запрос к указанному URL через tor и возвращает результат
func handleFetch(socksAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var fr fetchRequest
		if err := json.NewDecoder(r.Body).Decode(&fr); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		if fr.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
			return
		}

		client, err := httpClientViaSocks5(socksAddr, 25*time.Second)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create tor client", "detail": err.Error()})
			return
		}
		resp, err := client.Get(fr.URL)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed", "detail": err.Error()})
			return
		}
		defer resp.Body.Close()

		// stream back headers/body
		w.Header().Set("X-Proxy-Via", "tor")
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// handleCreateWithFetch создает новую заметку, если указан SourceURL, то сначала делает запрос к этому URL через tor и сохраняет результат в Content
func handleCreateWithFetch(socksAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in Entry
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}

		if in.SourceURL != "" {
			client, err := httpClientViaSocks5(socksAddr, 25*time.Second)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create tor client", "detail": err.Error()})
				return
			}
			resp, err := client.Get(in.SourceURL)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed", "detail": err.Error()})
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			_ = resp.Body.Close()
			in.Content = string(body)
			in.FetchedAt = time.Now().Unix()
		}

		storeMu.Lock()
		in.ID = nextID
		nextID++
		in.Created = time.Now().Unix()
		store[in.ID] = &in
		storeMu.Unlock()
		writeJSON(w, http.StatusCreated, in)
	}
}

// loggingMiddleware логирует запросы
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func main() {
	socksAddr := os.Getenv("TOR_SOCKS_ADDR")
	if socksAddr == "" {
		socksAddr = "tor:9050"
	}

	mux := http.NewServeMux()

	// CRUD
	mux.HandleFunc("/entries", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleList(w, r)
		case http.MethodPost:
			handleCreateWithFetch(socksAddr)(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/entries/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleCreate(w, r)
		case http.MethodGet:
			handleGet(w, r)
		case http.MethodPut:
			handleUpdate(w, r)
		case http.MethodDelete:
			handleDelete(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.Handle("/fetch", handleFetch(socksAddr))

	mux.HandleFunc("/_status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":    "ok",
			"tor_socks": socksAddr,
		})
	})

	srv := &http.Server{
		Addr:    ":8080",
		Handler: loggingMiddleware(mux),
	}

	// запуск сервера
	go func() {
		log.Printf("API starting on %s; tor socks: %s", srv.Addr, socksAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen failed: %v", err)
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Println("server stopped")
}
