package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"

	"github.com/cesar-yoab/authService/auth"
	"github.com/cesar-yoab/authService/graph/generated"
	"github.com/cesar-yoab/authService/graph/model"
)

var dbClient = auth.ConnectMongo()

func (r *mutationResolver) Register(ctx context.Context, registerInput *model.RegisterInput) (*model.Token, error) {
	input, err := auth.ValidateAndPrepare(registerInput)
	if err != nil {
		return nil, err
	}

	user, err := dbClient.RegisterUser(input)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *mutationResolver) UserAuth(ctx context.Context, auth *model.Authenticate) (*model.Token, error) {
	token, err := dbClient.AuthenticateUser(auth)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r *mutationResolver) RefreshToken(ctx context.Context, token *model.RefreshToken) (*model.Token, error) {
	newToken, err := auth.RefreshJWT(token)

	if err != nil {
		return nil, err
	}

	return newToken, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

type mutationResolver struct{ *Resolver }
