package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/trunov/goph-keeper/server/http/internal/storage/postgres"
	pb "github.com/trunov/goph-keeper/server/http/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	ID     string
	Conn   *websocket.Conn
	UserID int64
}

type Storager interface {
	StoreData(ctx context.Context, userID int64, data_type int, binary_data []byte, meta_info string) (*postgres.Credential, error)
	RetrieveCredentials(ctx context.Context, userID int64) ([]postgres.Credential, error)
}

type Handler struct {
	grpcClient pb.AuthClient
	storage    Storager
	version    string
	clients    map[string]*Client
	lock       sync.Mutex
}

type RegRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type StoreRequest struct {
	DataType   string `json:"data_type"`
	BinaryData []byte `json:"binary_data"`
	MetaInfo   string `json:"meta_info"`
	ClientID   string `json:"client_id"`
}

func NewHandler(grpcClient pb.AuthClient, storage Storager, version string) *Handler {
	return &Handler{grpcClient: grpcClient, storage: storage, version: version, clients: make(map[string]*Client)}
}

func (h *Handler) AddClient(client *Client) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.clients[client.ID] = client
}

func (h *Handler) RemoveClient(clientID string) {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.clients, clientID)
}

// TODO: Create errorhandler package

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var req RegRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.grpcClient.Register(ctx, &pb.RegisterRequest{Email: req.Email, Password: req.Password})
	if err != nil {
		grpcStatus, ok := status.FromError(err)
		if ok {
			if grpcStatus.Code() == codes.AlreadyExists {
				http.Error(w, grpcStatus.Message(), http.StatusConflict)
				return
			}

			http.Error(w, grpcStatus.Message(), http.StatusInternalServerError)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	fmt.Fprintf(w, "%d", response.UserID)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := h.grpcClient.Login(ctx, &pb.LoginRequest{Email: req.Email, Password: req.Password})
	if err != nil {
		grpcStatus, ok := status.FromError(err)
		if ok {
			if grpcStatus.Code() == codes.PermissionDenied {
				http.Error(w, grpcStatus.Message(), http.StatusForbidden)
				return
			}

			http.Error(w, grpcStatus.Message(), http.StatusInternalServerError)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	fmt.Fprintf(w, "%s", response.Token)
}

func (h *Handler) Store(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	authResp, err := h.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{
		Token: token,
	})
	if err != nil {
		// TODO: check if token is expired error than StatusUnauthorized else Internal
		fmt.Println(err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID := authResp.UserID

	fmt.Fprintf(w, "%d", userID)

	var req StoreRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	dataTypeToID := map[string]int{
		"Login/Password": 1,
		"Text data":      2,
		"Binary data":    3,
		"Bank card":      4,
	}

	cred, err := h.storage.StoreData(ctx, userID, dataTypeToID[req.DataType], req.BinaryData, req.MetaInfo)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.BroadcastToUser(cred, req.ClientID)

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) RetrieveCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	authResp, err := h.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{
		Token: token,
	})
	if err != nil {
		// TODO: Properly check the error type to distinguish between unauthorized and other errors
		fmt.Println(err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID := authResp.UserID

	credentials, err := h.storage.RetrieveCredentials(ctx, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving credentials: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(credentials)
	if err != nil {
		http.Error(w, "Failed to encode credentials", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.version))
}

func GenerateUniqueID() string {
	return uuid.New().String()
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		log.Println("Authorization token is required")
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	authResp, err := h.grpcClient.Authenticate(ctx, &pb.AuthenticateRequest{Token: token})
	if err != nil {
		log.Println("Unauthorized:", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	userID := authResp.UserID

	queryValues := r.URL.Query()
	clientID := queryValues.Get("clientID")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v\n", err)
		return
	}
	defer conn.Close()

	client := &Client{ID: clientID, Conn: conn, UserID: userID}
	h.AddClient(client)
	defer h.RemoveClient(clientID)

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v\n", err)
			break
		}

	}
}

func (h *Handler) BroadcastToUser(cred *postgres.Credential, excludedClientID string) {
	message := struct {
		Action string               `json:"action"`
		Data   *postgres.Credential `json:"data"`
	}{
		Action: "dataStored",
		Data:   cred,
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling message: %v", err)
		return
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	for _, client := range h.clients {
		// Check if the client's UserID matches before sending the message
		if client.UserID == cred.UserID && client.ID != excludedClientID {
			if err := client.Conn.WriteMessage(websocket.TextMessage, messageBytes); err != nil {
				log.Printf("Error broadcasting to client %s: %v", client.ID, err)
				// Optionally handle client disconnection here
			}
		}
	}
}

func NewRouter(h *Handler) chi.Router {
	r := chi.NewRouter()

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Post("/store", h.Store)

		r.Get("/store", h.RetrieveCredentials)
		r.Get("/version", h.GetVersion)
		r.Get("/ws", h.HandleWebSocket)
	})

	return r
}
