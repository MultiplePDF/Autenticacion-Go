package utils

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/smtp"
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

func SendEmail(email string, tempPassword string) map[string]string {
	smtpServer := "smtp.office365.com"
	auth := smtp.PlainAuth("", "multiple.pdf@outlook.com", "multiplepd*/", smtpServer)
	from := "multiple.pdf@outlook.com"
	to := []string{email}
	subject := "Password reset request"
	body := "Your temporary password is: " + tempPassword + "\n\n" +
		"Please click on the following link to reset your password:\n\n" +
		"https://mywebsite.com/reset-password"
	message := []byte("To: " + email + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")
	err := smtp.SendMail(smtpServer+":587", auth, from, to, message)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	return map[string]string{"message": "Se genero un correo con la nueva contraseña, revisa tu bandeja de entrada o spam."}
}
