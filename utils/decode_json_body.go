package utils

import (
	"encoding/json"
	"net/http"
)

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
