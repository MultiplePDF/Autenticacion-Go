package models

type UserReturn struct {
	ID    string `json:"id_user,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}
