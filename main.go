package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"crypto/md5"
	"encoding/hex"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	// Endopoint para validar token
	router.HandleFunc("/auth/get-user-details", getUserDetails).Methods("GET")

	// Endpoint para olvidar contraseña
	//router.HandleFunc("/forgot", ForgotPassword).Methods("POST")

	// Endpoint para reiniciar contraseña
	//router.HandleFunc("/reset/{token}", ResetPassword).Methods("POST")

	fmt.Println("Servidor iniciado...")
	log.Fatal(http.ListenAndServe(":4000", router))
}

// UserToJson representa la estructura de datos para un usuario
type UserToJson struct {
	Name            string `json:"name,omitempty"`
	LastName        string `json:"lastname,omitempty"`
	Email           string `json:"email,omitempty"`
	Password        string `json:"password,omitempty"`
	ConfirmPassword string `json:"confirm_password,omitempty"`
}

type UserMongoDB struct {
	ID        string    `json:"id_user,omitempty"`
	Name      string    `json:"name,omitempty"`
	LastName  string    `json:"lastname,omitempty"`
	Email     string    `json:"email,omitempty"`
	Password  string    `json:"password,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"update_at,omitempty"`
}

// Token representa la estructura de datos para un token JWT
type Token struct {
	Token string `json:"token,omitempty"`
}

// MongoDBConfig representa la configuración para la conexión a la base de datos MongoDB
type MongoDBConfig struct {
	URI            string
	DBName         string
	CollectionName string
}

func mongoDBConfig() MongoDBConfig {
	return MongoDBConfig{
		URI:            "mongodb://localhost:27017",
		DBName:         "multiple_pdf_database",
		CollectionName: "users",
	}
}
func conectMongoDB() (*mongo.Client, error) {
	// Obtener la configuración de MongoDB
	config := mongoDBConfig()

	// Establecer las opciones de conexión a MongoDB
	clientOptions := options.Client().ApplyURI(config.URI)

	// Establecer la conexión a MongoDB
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Error al establecer la conexión a MongoDB: %v", err)
		return nil, err
	}

	// Comprobar si la conexión es válida
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("Error al verificar la conexión a MongoDB: %v", err)
		return nil, err
	}

	fmt.Println("Conexión exitosa a MongoDB")

	return client, nil
}

// Crea un nuevo usuario en la base de datos
func register(w http.ResponseWriter, r *http.Request) {
	var user UserToJson
	err := decodeJSONBody(w, r, &user)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	if user.Name == "" || user.LastName == "" || user.Email == "" || user.Password == "" || user.ConfirmPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Todos los campos son obligatorios!")
		return
	}
	if len(user.Password) < 8 {
		respondWithError(w, http.StatusBadRequest, "La contraseña debe tener más de 8 caracteres")
		return
	}

	if user.Password != user.ConfirmPassword {
		respondWithError(w, http.StatusBadRequest, "No coinciden las contraseñas")
		return
	}

	// Conecta a la base de datos
	client, err := conectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	collection := client.Database(mongoDBConfig().DBName).Collection(mongoDBConfig().CollectionName)
	filter := bson.M{"email": user.Email}

	var existingUser UserToJson
	err = collection.FindOne(context.Background(), filter).Decode(&existingUser)

	if err == nil {
		// El correo electrónico ya existe en la base de datos
		respondWithError(w, http.StatusConflict, "El correo electrónico ya está registrado")
		return
	} else if err != mongo.ErrNoDocuments {
		// Ocurrió un error al buscar en la base de datos
		respondWithError(w, http.StatusConflict, "Error, intentelo más tarde")
		return
	}

	// Encripta la contraseña antes de guardarla en la base de datos
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	newUser := UserMongoDB{
		ID:        hashEmail(user.Email),
		Name:      user.Name,
		LastName:  user.LastName,
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

	var usuarioCreado UserToJson
	err = collection.FindOne(context.Background(), filter).Decode(&usuarioCreado)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Retorna el token

	tokenString, err := generateTokenJWT(hashEmail(user.Email))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error al generar el token JWT "+err.Error())
		return
	}

	// Retorna el token JWT
	respondWithJSON(w, http.StatusOK, Token{Token: tokenString})
}

// Inicia sesión de un usuario y genera un token JWT
func login(w http.ResponseWriter, r *http.Request) {
	var user UserToJson
	err := decodeJSONBody(w, r, &user)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	// Conecta a la base de datos
	client, err := conectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Busca el usuario por email
	collection := client.Database(mongoDBConfig().DBName).Collection(mongoDBConfig().CollectionName)
	filter := bson.M{"email": user.Email}
	var resultado UserToJson
	err = collection.FindOne(context.Background(), filter).Decode(&resultado)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Compara la contraseña ingresada con la almacenada en la base de datos
	err = bcrypt.CompareHashAndPassword([]byte(resultado.Password), []byte(user.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Genera un nuevo token JWT
	token, err := generateTokenJWT(hashEmail(resultado.Email))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error al generar el token JWT "+err.Error())
		return
	}

	// Retorna el token JWT
	respondWithJSON(w, http.StatusOK, Token{Token: token})
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

func getUserByID(userID string) (UserMongoDB, error) {
	// Conecta a la base de datos
	client, err := conectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Busca el usuario por email
	collection := client.Database(mongoDBConfig().DBName).Collection(mongoDBConfig().CollectionName)
	filter := bson.M{"id": userID}

	var user UserMongoDB
	err = collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return UserMongoDB{}, err
	}

	// Devuelve el usuario
	return user, nil
}

// Función para validar un token JWT
func validateTokenString(tokenString string) (UserMongoDB, error) {

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
		return UserMongoDB{}, err
	}
	if !token.Valid {
		return UserMongoDB{}, fmt.Errorf("token is not valid")
	}

	// Obtiene el usuario desde la base de datos de MongoDB
	userID := tokenClaims.UserID
	user, err := getUserByID(userID)
	if err != nil {
		return UserMongoDB{}, err
	}

	// Devuelve el usuario
	return user, nil
}

func getUserDetails(w http.ResponseWriter, r *http.Request) {
	// Obtiene el token JWT desde el encabezado "Authorization" de la petición
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		respondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}

	// Valida el token JWT y obtiene el usuario correspondiente desde la base de datos
	user, err := validateTokenString(tokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Ha ocurrido un error: "+err.Error())
		return
	}

	// Devuelve el usuario en la respuesta
	respondWithJSON(w, http.StatusOK, UserMongoDB{Name: user.Name, LastName: user.LastName, Email: user.Email})
}

// Decodifica el cuerpo de una solicitud HTTP en formato JSON y lo asigna a una estructura dada
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	defer r.Body.Close()

	// Limita el tamaño máximo del cuerpo de la solicitud a 1 MB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Decodifica el cuerpo de la solicitud en formato JSON
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(v)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return err
	}

	return nil
}

// Responde con un error en formato JSON
func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	respondWithJSON(w, statusCode, map[string]string{"error": message})
}

// Responde con datos en formato JSON
func respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println("Error al responder con JSON:", err)
	}
}

func hashEmail(email string) string {
	hash := md5.Sum([]byte(email))
	return hex.EncodeToString(hash[:])
}
