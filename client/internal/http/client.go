package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/rivo/tview"
	log "github.com/sirupsen/logrus"
)

type CredentialManager struct {
	sync.Mutex
	Credentials []Credential
	App         *tview.Application
	TextView    *tview.TextView // This might be dynamically set based on the current UI context
}

func (cm *CredentialManager) SetCredentials(creds []Credential) {
	cm.Lock()
	defer cm.Unlock()

	cm.Credentials = creds
}

func (cm *CredentialManager) UpdateUI() {
	cm.App.QueueUpdateDraw(func() {
		cm.TextView.Clear()
		cm.Lock()
		for _, cred := range cm.Credentials {
			fmt.Fprintf(cm.TextView, "DataType: %d\nBinaryData: %s\nMetaInfo: %s\n\n", cred.DataType, cred.BinaryData, cred.MetaInfo)
		}
		cm.Unlock()
	})
}

// Client holds the Resty client instance.
type Client struct {
	Resty        *resty.Client
	BaseURL      string
	JWTToken     string
	WSConn       *websocket.Conn
	shutdownChan chan struct{}
	CredManager  *CredentialManager
	ClientID     string
}

type Credential struct {
	DataType   int    `json:"data_type"`
	BinaryData []byte `json:"binary_data"`
	MetaInfo   string `json:"meta_info"`
}

// NewClient creates a new HTTP client.
func NewClient(baseURL string, credManager *CredentialManager, clientID string) *Client {
	return &Client{
		Resty:        resty.New(),
		BaseURL:      baseURL,
		shutdownChan: make(chan struct{}),
		CredManager:  credManager,
		ClientID:     clientID,
	}
}

// RegRequest represents the registration request payload.
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
	BinaryData []byte `json:"binary_data"` // Assuming it's base64 encoded string
	MetaInfo   string `json:"meta_info"`
	ClientID   string `json:"client_id"`
}

// Register performs the registration request to the given URL.
func (c *Client) Register(req RegRequest) (*resty.Response, error) {
	fullUrl := c.BaseURL + "/register"
	resp, err := c.Resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody(req).
		Post(fullUrl)

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) Login(req LoginRequest) (*resty.Response, error) {
	fullUrl := c.BaseURL + "/login"
	resp, err := c.Resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody(req).
		Post(fullUrl)

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) FetchVersion() (string, error) {
	fullUrl := c.BaseURL + "/version"
	resp, err := c.Resty.R().
		Get(fullUrl)

	if err != nil {
		return "", err
	}

	return string(resp.Body()), nil
}

func (c *Client) Store(req StoreRequest) (*resty.Response, error) {
	log.Info("token", c.JWTToken)
	fullUrl := c.BaseURL + "/store"
	resp, err := c.Resty.R().
		SetHeader("Content-Type", "application/json").
		SetAuthToken(c.JWTToken).
		SetBody(req).
		Post(fullUrl)

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) RetrieveCredentials() ([]Credential, error) {
	fullUrl := c.BaseURL + "/store"
	resp, err := c.Resty.R().
		SetHeader("Accept", "application/json").
		SetAuthToken(c.JWTToken).
		Get(fullUrl)

	if err != nil {
		log.Errorf("Failed to retrieve credentials: %v", err)
		return nil, err
	}

	if resp.IsError() {
		log.Errorf("Error response from server: %v", resp.String())
		return nil, fmt.Errorf("server responded with error: %s", resp.Status())
	}

	var credentials []Credential
	err = json.Unmarshal(resp.Body(), &credentials)
	if err != nil {
		log.Errorf("Error unmarshalling credentials response: %v", err)
		return nil, err
	}

	return credentials, nil
}

func (c *Client) ConnectToWebSocket() {
	u := url.URL{Scheme: "ws", Host: "localhost:3000", Path: "/api/v1/ws", RawQuery: "clientID=" + url.QueryEscape(c.ClientID)}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+c.JWTToken)

	log.Printf("connecting to %s", u.String())

	var err error
	c.WSConn, _, err = websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket: %v", err)
	}

	// Setup channel to handle interrupt signal for graceful shutdown alongside application-controlled shutdown
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM) // Listen for Ctrl+C and SIGTERM

	go func() {
		defer c.WSConn.Close()
		for {
			select {
			case <-c.shutdownChan: // Application-controlled shutdown
				log.Println("Received shutdown signal, closing WebSocket connection")
				return
			case <-interrupt: // OS interrupt signal
				log.Println("Received OS interrupt signal, closing WebSocket connection")
				return
			default:
				_, message, err := c.WSConn.ReadMessage()
				if err != nil {
					log.Printf("Error reading from WebSocket: %v", err)
					return
				}

				var msg struct {
					Action string     `json:"action"`
					Data   Credential `json:"data"`
				}

				if err := json.Unmarshal(message, &msg); err == nil && msg.Action == "dataStored" {
					c.CredManager.Lock()
					c.CredManager.Credentials = append(c.CredManager.Credentials, msg.Data)
					c.CredManager.Unlock()

					c.CredManager.UpdateUI()
				}
				log.Printf("Received message: %s", message)
			}
		}
	}()
}

func (c *Client) ShutdownWS() {
	if c.shutdownChan != nil {
		close(c.shutdownChan) // Signal the shutdown
	}
	if c.WSConn != nil {
		c.WSConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.WSConn.Close()
	}
}
