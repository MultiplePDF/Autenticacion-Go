package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AndreyHernandezT/serverAuth/database"
	"github.com/AndreyHernandezT/serverAuth/models"
	"github.com/AndreyHernandezT/serverAuth/repositories"
	"github.com/AndreyHernandezT/serverAuth/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("private.rsa")
	if err != nil {
		log.Fatal("Cannot read private key file")
	}
	publicBytes, err := ioutil.ReadFile("public.rsa.pub")
	if err != nil {
		log.Fatal("Cannot read public key file")
	}
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("Cannot parce private key")
	}
	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("Cannot parce private key")
	}
	fmt.Println("Servidor iniciado...")
}

func main() {
	router := mux.NewRouter()

	// Endpoint para registrar un nuevo usuario
	router.HandleFunc("/auth/register", register).Methods("POST")

	// Endpoint para iniciar sesión
	router.HandleFunc("/auth/login", login).Methods("POST")

	// Endopoint para devolver un usuario
	router.HandleFunc("/auth/get-user-details", getUserDetails).Methods("GET")

	// Endopoint para validar token
	router.HandleFunc("/auth/validate", validateToken).Methods("GET")

	// Endopoint para devolver id de usuario
	router.HandleFunc("/auth/get-userid", getUserIDByToken).Methods("GET")

	// Endopoint para actualizar un usuario
	router.HandleFunc("/auth/update-user", updateUser).Methods("PUT")

	// Endpoint para olvidar contraseña
	router.HandleFunc("/auth/forgot-password", forgotPassword).Methods("POST")

	// Endpoint para cambiar contraseña
	router.HandleFunc("/auth/change-password", changePassword).Methods("POST")

	log.Fatal(http.ListenAndServe(":4000", router))
}

// Crea un nuevo usuario en la base de datos
func register(w http.ResponseWriter, r *http.Request) {
	var user models.UserToJson
	err := utils.DecodeJSONBody(w, r, &user)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	user.Email = strings.ToLower(user.Email)

	if user.Name == "" || user.Email == "" || user.Password == "" || user.ConfirmPassword == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Todos los campos son obligatorios!")
		return
	}
	if len(user.Password) < 8 {
		utils.RespondWithError(w, http.StatusBadRequest, "La contraseña debe tener más de 8 caracteres")
		return
	}

	if user.Password != user.ConfirmPassword {
		utils.RespondWithError(w, http.StatusBadRequest, "No coinciden las contraseñas")
		return
	}

	// Conecta a la base de datos
	client, err := database.ConectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	collection := client.Database(database.MongoDBConfig().DBName).Collection(database.MongoDBConfig().CollectionName)
	filter := bson.M{"email": user.Email}

	var existingUser models.UserToJson
	err = collection.FindOne(context.Background(), filter).Decode(&existingUser)

	if err == nil {
		// El correo electrónico ya existe en la base de datos
		utils.RespondWithError(w, http.StatusConflict, "El correo electrónico ya está registrado")
		return
	} else if err != mongo.ErrNoDocuments {
		// Ocurrió un error al buscar en la base de datos
		utils.RespondWithError(w, http.StatusConflict, "Error, intentelo más tarde")
		return
	}

	// Encripta la contraseña antes de guardarla en la base de datos
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	newUser := models.UserMongoDB{
		ID:        utils.HashEmail(user.Email),
		Name:      user.Name,
		Email:     user.Email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Inserta el usuario en la colección
	_, err = collection.InsertOne(context.Background(), newUser)
	if err != nil {
		log.Fatal(err)
	}

	var usuarioCreado models.UserToJson
	err = collection.FindOne(context.Background(), filter).Decode(&usuarioCreado)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Retorna el token

	tokenString, err := generateTokenJWT(utils.HashEmail(user.Email))
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error al generar el token JWT "+err.Error())
		return
	}

	// Retorna el token JWT
	utils.RespondWithJSON(w, http.StatusOK, models.Token{Token: tokenString})
}

// Inicia sesión de un usuario y genera un token JWT
func login(w http.ResponseWriter, r *http.Request) {
	var user models.UserToJson
	err := utils.DecodeJSONBody(w, r, &user)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	// Conecta a la base de datos
	client, err := database.ConectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Busca el usuario por email
	collection := client.Database(database.MongoDBConfig().DBName).Collection(database.MongoDBConfig().CollectionName)
	filter := bson.M{"email": user.Email}
	var resultado models.UserToJson
	err = collection.FindOne(context.Background(), filter).Decode(&resultado)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Compara la contraseña ingresada con la almacenada en la base de datos
	err = bcrypt.CompareHashAndPassword([]byte(resultado.Password), []byte(user.Password))
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Genera un nuevo token JWT
	token, err := generateTokenJWT(utils.HashEmail(resultado.Email))
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error al generar el token JWT "+err.Error())
		return
	}

	// Retorna el token JWT
	utils.RespondWithJSON(w, http.StatusOK, models.Token{Token: token})
}

// Genera un token JWT para el ID de usuario dado
func generateTokenJWT(userEmail string) (string, error) {
	// Crea el token con el algoritmo HS256 y la clave secreta
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": userEmail,
		"exp": time.Now().Add(time.Hour * 24).Unix(), // Expira en 24 horas
	})

	// Firma el token con la clave secreta
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Función para validar un token JWT
func validateTokenString(tokenString string) (models.UserMongoDB, error) {
	type TokenValidate struct {
		UserID string `json:"sub"`
		jwt.StandardClaims
	}

	tokenClaims := &TokenValidate{}
	token, err := jwt.ParseWithClaims(tokenString, tokenClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return models.UserMongoDB{}, err
	}
	if !token.Valid {
		return models.UserMongoDB{}, fmt.Errorf("token is not valid")
	}

	// Obtiene el usuario desde la base de datos de MongoDB
	userID := tokenClaims.UserID
	user, err := repositories.GetUserByID(userID)
	if err != nil {
		return models.UserMongoDB{}, err
	}

	// Devuelve el usuario
	return user, nil
}

// Valida si el token es válido
func validateToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}
	_, err := validateTokenString(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Error al validar el token "+err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "true"})
}

// Devuelve a un usuario
func getUserDetails(w http.ResponseWriter, r *http.Request) {
	// Obtiene el token JWT desde el encabezado "Authorization" de la petición
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}

	// Valida el token JWT y obtiene el usuario correspondiente desde la base de datos
	user, err := validateTokenString(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Ha ocurrido un error: "+err.Error())
		return
	}
	// Devuelve el usuario en la respuesta
	utils.RespondWithJSON(w, http.StatusOK, models.UserMongoDB{Name: user.Name, Email: user.Email, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt})
}

// Devuelve el ID de un usuario según el token
func getUserIDByToken(w http.ResponseWriter, r *http.Request) {
	// Obtiene el token JWT desde el encabezado "Authorization" de la petición
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}

	// Valida el token JWT y obtiene el usuario correspondiente desde la base de datos
	user, err := validateTokenString(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Ha ocurrido un error: "+err.Error())
		return
	}

	// Devuelve el usuario en la respuesta
	utils.RespondWithJSON(w, http.StatusOK, models.UserReturn{ID: user.ID})
}

// Actualiza el nombre y email de un usuario
func updateUser(w http.ResponseWriter, r *http.Request) {
	// Obtiene el token JWT desde el encabezado "Authorization" de la petición
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}

	// Valida el token JWT y obtiene el usuario correspondiente desde la base de datos
	existingUser, err := validateTokenString(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Ha ocurrido un error: "+err.Error())
		return
	}

	var user models.UserMongoDB
	err = utils.DecodeJSONBody(w, r, &user)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	existingUser, err = repositories.GetUserByID(existingUser.ID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	if user.Name != "" {
		existingUser.Name = user.Name
	}

	existingUser.UpdatedAt = time.Now()

	err = repositories.UpdateUser(&existingUser)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error updating user")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, models.UserReturn{Name: user.Name, Email: user.Email})
}

// Devuelve el ID de un usuario según el token
func changePassword(w http.ResponseWriter, r *http.Request) {
	// Obtiene el token JWT desde el encabezado "Authorization" de la petición
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}

	// Valida el token JWT y obtiene el usuario correspondiente desde la base de datos
	existingUser, err := validateTokenString(tokenString)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Ha ocurrido un error: "+err.Error())
		return
	}

	var newPassword models.NewPassword
	err = utils.DecodeJSONBody(w, r, &newPassword)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	existingUser, err = repositories.GetUserByID(existingUser.ID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	if newPassword.ActualPassword == "" || newPassword.Password == "" || newPassword.ConfirmPassword == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Todos los campos son obligatorios!")
		return
	}

	if len(newPassword.Password) < 8 {
		utils.RespondWithError(w, http.StatusBadRequest, "La contraseña debe tener más de 8 caracteres")
		return
	}

	if newPassword.Password != newPassword.ConfirmPassword {
		utils.RespondWithError(w, http.StatusBadRequest, "No coinciden las contraseñas")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(newPassword.ActualPassword))
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "La contraseña no coincide")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	existingUser.Password = string(hashedPassword)

	existingUser.UpdatedAt = time.Now()

	err = repositories.ChangePasswordDB(&existingUser)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error updating user")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Contraseña cambiada correctamente"})
}

// Envia un correo al usuario para que cambie su contraseña
func forgotPassword(w http.ResponseWriter, r *http.Request) {
	// Obtiene el token JWT desde el encabezado "Authorization" de la petición

	var forgotPasswordModel models.ForgotPassword
	err := utils.DecodeJSONBody(w, r, &forgotPasswordModel)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	existingUser, err := repositories.GetUserByEmail(forgotPasswordModel.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}
	newPassword := uuid.NewV4().String()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	existingUser.Password = string(hashedPassword)
	existingUser.UpdatedAt = time.Now()

	err = repositories.ChangePasswordDB(&existingUser)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error updating user")
		return
	}

	err = utils.SendEmail(existingUser.Email, newPassword)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error send email")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "Se genero un correo con una contraseña contraseña temporal, revisa tu bandeja de entrada o spam."})
}
