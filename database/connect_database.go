package database

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConectMongoDB() (*mongo.Client, error) {
	// Obtener la configuración de MongoDB
	config := MongoDBConfig()

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
