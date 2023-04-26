package repositories

import (
	"context"
	"log"

	"github.com/AndreyHernandezT/serverAuth/database"
	"github.com/AndreyHernandezT/serverAuth/models"
	"go.mongodb.org/mongo-driver/bson"
)

func UpdateUser(user *models.UserMongoDB) error {
	// Creamos un filtro para buscar el usuario a actualizar
	filter := bson.M{"id": user.ID}

	// Creamos un documento con los nuevos datos del usuario
	update := bson.M{
		"$set": bson.M{
			"name":      user.Name,
			"email":     user.Email,
			"updatedat": user.UpdatedAt,
		},
	}

	// Conecta a la base de datos
	client, err := database.ConectMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	collection := client.Database(database.MongoDBConfig().DBName).Collection(database.MongoDBConfig().CollectionName)
	_, err = collection.UpdateOne(context.Background(), filter, update)

	if err != nil {
		return err
	}

	return nil
}
