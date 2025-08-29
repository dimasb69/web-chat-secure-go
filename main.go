package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	clients   = make(map[*websocket.Conn]string)
	broadcast = make(chan Message)
	mutex     = sync.Mutex{}
)

type Message struct {
	Username    string `json:"username"`
	Content     string `json:"content"`
	IsMentioned bool   `json:"isMentioned"`
}

func main() {
	logFile, err := os.OpenFile("chat.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	fmt.Println("Chat en tiempo real con WebSockets iniciado en :8443")
	http.HandleFunc("/ws", handleConnections)

	fs := http.FileServer(http.Dir("static"))
	wrappedFs := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")

		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		switch ext {
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case ".js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case ".html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		fs.ServeHTTP(w, r)
	})
	http.Handle("/static/", http.StripPrefix("/static/", wrappedFs))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "static/index.html")
			return
		}
		http.NotFound(w, r)
	})

	go handleMessages()
	// Cambiar a ListenAndServeTLS para habilitar SSL
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error al actualizar a WebSocket: %v", err)
		return
	}
	defer conn.Close()

	username := generateUsername()
	mutex.Lock()
	clients[conn] = username
	mutex.Unlock()

	initMsg := Message{
		Username:    username,
		Content:     encryptMessage("Se ha conectado al chat"),
		IsMentioned: false,
	}
	err = conn.WriteJSON(initMsg)
	if err != nil {
		log.Printf("Error al enviar mensaje inicial: %v", err)
		return
	}

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			mutex.Lock()
			delete(clients, conn)
			mutex.Unlock()
			break
		}

		// Actualizar el nombre de usuario en el mapa de clientes
		if msg.Username != "" {
			clients[conn] = msg.Username
		}

		content := decryptMessage(msg.Content)
		if content == "" {
			log.Printf("Error: contenido del mensaje vacío o inválido")
			continue
		}

		mentions := extractMentions(content)
		content = removeMentions(content)
		msg.Content = encryptMessage(content)

		log.Printf("Mensaje recibido de %s: %s", encryptMessage(msg.Username), encryptMessage(content)) // Encriptar el nombre de usuario
		msg.IsMentioned = len(mentions) > 0
		broadcast <- msg
	}
}

func handleMessages() {
	for {
		msg := <-broadcast
		mutex.Lock()
		for client, username := range clients {
			msgCopy := msg
			if strings.Contains(decryptMessage(msg.Content), "@"+username) {
				msgCopy.IsMentioned = true
			}
			err := client.WriteJSON(msgCopy)
			if err != nil {
				client.Close()
				delete(clients, client)
			}
		}
		mutex.Unlock()
	}
}

func encryptMessage(content string) string {
	return base64.StdEncoding.EncodeToString([]byte(content))
}

func decryptMessage(encryptedContent string) string {
	decoded, err := base64.StdEncoding.DecodeString(encryptedContent)
	if err != nil {
		log.Println("Error al desencriptar mensaje:", err)
		return ""
	}
	return string(decoded)
}

func generateUsername() string {
	randGen := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("@user%d", randGen.Intn(10000))
}

func extractMentions(content string) map[string]bool {
	mentions := make(map[string]bool)
	re := regexp.MustCompile(`@\w+`)
	for _, mention := range re.FindAllString(content, -1) {
		mentions[strings.TrimPrefix(mention, "@")] = true
	}
	return mentions
}

func removeMentions(content string) string {
	re := regexp.MustCompile(`@\w+`)
	return re.ReplaceAllString(content, "")
}