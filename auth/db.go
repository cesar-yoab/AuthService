package auth

// Contains all the logic to connect the API to our Mongo database
// This package also leverages some helper functions for
// authentication located in the util.go file

import (
	"log"
	"time"

	"github.com/cesar-yoab/authService/graph/model"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/context"
)

// DB wraps the mongo.Client object
type DB struct {
	client     *mongo.Client
	database   string
	collection string
}

// UserModel representation of data in database
type UserModel struct {
	ID       primitive.ObjectID `bson:"_id" json:"_id,omitempty"`
	Fname    string             `json:"fname"`
	Lname    string             `json:"lname"`
	Email    string             `json:"email"`
	Username string             `json:"username"`
	Password string             `json:"password"`
}

// ConnectMongo to database and return a pointer to a DB object
func ConnectMongo() *DB {
	// Get URI from .env file
	uri := getFromEnv("DB")
	dtb := getFromEnv("DBNAME")
	coll := getFromEnv("COLLECTION")
	if uri == "" {
		log.Fatal("Unable to access .env database variable")
	}

	// Connect to database
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)

	return &DB{
		client:     client,
		database:   dtb,
		collection: coll,
	}
}

// CreateUser fills struct values for insertion in database
func CreateUser(input *model.RegisterInput) *UserModel {
	return &UserModel{
		ID:       primitive.NewObjectID(),
		Fname:    input.Fname,
		Lname:    input.Lname,
		Email:    input.Email,
		Username: input.Username,
		Password: input.Password,
	}
}

// RegisterUser a new user into the database, this function asumes input validation has been performed
func (db *DB) RegisterUser(input *model.RegisterInput) (*model.Token, error) {
	// Select our mongo collection
	collection := db.client.Database(db.database).Collection(db.collection)

	// Connect
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check that we don't have any duplicates
	if user, _ := db.FindByUsername(input.Username); user != nil {
		return nil, gqlerror.Errorf("Username %s taken.", input.Username)
	}
	if user, _ := db.FindByEmail(input.Email); user != nil {
		return nil, gqlerror.Errorf("Email %s taken.", input.Email)
	}

	user := CreateUser(input)

	// Insert to collection
	res, err := collection.InsertOne(ctx, user)
	if err != nil {
		log.Fatal(err)
	}

	// If insertion is successful generate token
	token, err := generateToken(jwt.MapClaims{
		"_id":      res.InsertedID.(primitive.ObjectID).Hex(),
		"username": input.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	// return token
	return &model.Token{
		Jwt: token,
	}, nil
}

// FindByUsername utility function from the Mongo database
func (db *DB) FindByUsername(username string) (*model.User, error) {
	// Filter to pass to the mongo Find function
	filter := bson.M{"username": username}

	return db.findWithFilter(filter)
}

// FindByEmail in database
func (db *DB) FindByEmail(email string) (*model.User, error) {
	filter := bson.M{"email": email}

	return db.findWithFilter(filter)
}

// findWithFilter in the database, this is to avoid repeating code
func (db *DB) findWithFilter(filter bson.M) (*model.User, error) {
	collection := db.client.Database(db.database).Collection(db.collection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Where we store the resulting values
	var user UserModel
	// Search in our database
	if res := collection.FindOne(ctx, filter).Decode(&user); res != nil {
		// return nil if we couldn't find it or something else happened
		return nil, res
	}

	// If nothing goes wrong then return
	return &model.User{
		ID:       user.ID.Hex(),
		Username: user.Username,
	}, nil
}

// FindUser from database and return
func (db *DB) FindUser(email string) (*UserModel, error) {
	collection := db.client.Database(db.database).Collection(db.collection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// To store user
	var user UserModel
	// Search in database
	if res := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user); res != nil {
		// Something went wrong
		return nil, res
	}

	return &user, nil
}

// AuthenticateUser and return a token
func (db *DB) AuthenticateUser(auth *model.Authenticate) (*model.Token, error) {
	user, err := db.FindUser(auth.Email)
	if err != nil {
		return nil, gqlerror.Errorf("Could not find user with email '%s'.", auth.Email)
	}

	if !ComparePasswords([]byte(user.Password), []byte(auth.Password)) {
		return nil, gqlerror.Errorf("Passwords don't match.")
	}

	// If passwords match then we issue a token for the user
	token, err := generateToken(jwt.MapClaims{
		"_id":      user.ID.Hex(),
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	// Finally return a token for graphql
	return &model.Token{
		Jwt: token,
	}, nil
}
