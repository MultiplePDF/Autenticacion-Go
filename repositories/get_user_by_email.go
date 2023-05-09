package repositories

import (
	"context"
	"log"

	"github.com/AndreyHernandezT/serverAuth/database"
	"github.com/AndreyHernandezT/serverAuth/models"
	"go.mongodb.org/mongo-driver/bson"
)

func GetUserByEmail(email string) (models.UserMongoDB, error) {
	// Conecta a la base de datos
	client, err := database.ConectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Busca el usuario por email
	collection := client.Database(database.MongoDBConfig().DBName).Collection(database.MongoDBConfig().CollectionName)
	filter := bson.M{"email": email}

	var user models.UserMongoDB
	err = collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return models.UserMongoDB{}, err
	}

	// Devuelve el usuario
	return user, nil
}
