package models

// UserToJson representa la estructura de datos para un usuario
type NewPassword struct {
	ActualPassword  string `json:"actual_password,omitempty"`
	Password        string `json:"password,omitempty"`
	ConfirmPassword string `json:"confirm_password,omitempty"`
}
