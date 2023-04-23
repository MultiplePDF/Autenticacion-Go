package models

// MongoDBConfig representa la configuración para la conexión a la base de datos MongoDB
type MongoDBConfig struct {
	URI            string
	DBName         string
	CollectionName string
}
