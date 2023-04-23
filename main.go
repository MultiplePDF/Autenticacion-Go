package main

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/AndreyHernandezT/serverAuth/database"
	"github.com/AndreyHernandezT/serverAuth/models"
	"github.com/AndreyHernandezT/serverAuth/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
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

	// Endpoint para olvidar contraseña
	//router.HandleFunc("/forgot", ForgotPassword).Methods("POST")

	// Endpoint para reiniciar contraseña
	//router.HandleFunc("/reset/{token}", ResetPassword).Methods("POST")

	fmt.Println("Servidor iniciado...")
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
		ID:        hashEmail(user.Email),
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

	tokenString, err := generateTokenJWT(hashEmail(user.Email))
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
	token, err := generateTokenJWT(hashEmail(resultado.Email))
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

func getUserByID(userID string) (models.UserReturn, error) {
	// Conecta a la base de datos
	client, err := database.ConectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Busca el usuario por email
	collection := client.Database(database.MongoDBConfig().DBName).Collection(database.MongoDBConfig().CollectionName)
	filter := bson.M{"id": userID}

	var user models.UserReturn
	err = collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return models.UserReturn{}, err
	}

	// Devuelve el usuario
	return user, nil
}

// Función para validar un token JWT
func validateTokenString(tokenString string) (models.UserReturn, error) {
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
		return models.UserReturn{}, err
	}
	if !token.Valid {
		return models.UserReturn{}, fmt.Errorf("token is not valid")
	}

	// Obtiene el usuario desde la base de datos de MongoDB
	userID := tokenClaims.UserID
	user, err := getUserByID(userID)
	if err != nil {
		return models.UserReturn{}, err
	}

	// Devuelve el usuario
	return user, nil
}

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
	utils.RespondWithJSON(w, http.StatusOK, models.UserReturn{Name: user.Name, Email: user.Email})
}

func hashEmail(email string) string {
	hash := md5.Sum([]byte(email))
	return hex.EncodeToString(hash[:])
}
