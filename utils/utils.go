package utils

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"gopkg.in/gomail.v2"
)

// Responde con datos en formato JSON
func RespondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println("Error al responder con JSON:", err)
	}
}

// Responde con un error en formato JSON
func RespondWithError(w http.ResponseWriter, statusCode int, message string) {
	RespondWithJSON(w, statusCode, map[string]string{"error": message})
}

func HashEmail(email string) string {
	hash := md5.Sum([]byte(email))
	return hex.EncodeToString(hash[:])
}

// Decodifica el cuerpo de una solicitud HTTP en formato JSON y lo asigna a una estructura dada
func DecodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	defer r.Body.Close()

	// Limita el tamaño máximo del cuerpo de la solicitud a 1 MB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Decodifica el cuerpo de la solicitud en formato JSON
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(v)

	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return err
	}

	return nil
}

func SendEmail(email string, tempPassword string) error {

	msg := gomail.NewMessage()
	msg.SetHeader("From", "gosoylinda@gmail.com")
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", "Contraseña temporal generada")
	body := "<p>Tu contraseña temporal es :<p>\n\n <strong><code>" + tempPassword + "</code></strong> \n\n" +
		"<p>Inicia sesión con esta contraseña para ingresar. Recuerda cambiar la contraseña inmediatamente.</p>" +
		"<p><a href='https://cliente1.bucaramanga.upb.edu.co/SignIn'>https://cliente1.bucaramanga.upb.edu.co/SignIn</a>"
	msg.SetBody("text/html", body)

	n := gomail.NewDialer("smtp.gmail.com", 587, "gosoylinda@gmail.com", "rrrxpbtcdldkhhgm")

	// Send the email
	if err := n.DialAndSend(msg); err != nil {
		return err
	}
	return nil
}
