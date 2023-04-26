package database

import "github.com/AndreyHernandezT/serverAuth/models"

func MongoDBConfig() models.MongoDBConfig {
	return models.MongoDBConfig{
		URI:            "mongodb://localhost:27017",
		DBName:         "multiple_pdf_database",
		CollectionName: "users",
	}
}
