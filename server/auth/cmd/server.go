package main

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	j "github.com/golang-jwt/jwt/v5"
	"github.com/trunov/goph-keeper/server/auth/internal/domain/models"
	"github.com/trunov/goph-keeper/server/auth/internal/lib/jwt"
	"github.com/trunov/goph-keeper/server/auth/internal/storage/postgres"
	pb "github.com/trunov/goph-keeper/server/auth/proto"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Storager interface {
	RegisterUser(ctx context.Context, email, password string) (userID int64, err error)
	FindUser(ctx context.Context, email string) (user models.User, err error)
}

type AuthServer struct {
	pb.UnimplementedAuthServer
	storage    Storager
	jwtService jwt.JWTService
}

func NewAuthServer(storage Storager, jwtService jwt.JWTService) *AuthServer {
	return &AuthServer{storage: storage, jwtService: jwtService}
}

func (s *AuthServer) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	userID, err := s.storage.RegisterUser(ctx, in.Email, string(hashedPassword))
	if err != nil {
		if strings.Contains(err.Error(), "unique constraint violation") {
			return nil, status.Errorf(codes.AlreadyExists, "user with email %s already exists", in.Email)
		}
		return nil, status.Errorf(codes.Internal, "error registering user: %v", err)
	}

	return &pb.RegisterResponse{UserID: userID}, nil
}

func (s *AuthServer) Login(ctx context.Context, in *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, err := s.storage.FindUser(ctx, in.Email)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			return nil, status.Error(codes.PermissionDenied, "email or password is incorrect")
		}

		log.Printf("internal error ocurred while finding user: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password)); err != nil {
		return nil, status.Error(codes.PermissionDenied, "email or password is incorrect")
	}

	token, err := s.jwtService.NewToken(user, time.Hour*2)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &pb.LoginResponse{Token: token}, nil
}

func (s *AuthServer) Authenticate(ctx context.Context, in *pb.AuthenticateRequest) (*pb.AuthenticateResponse, error) {
	token, err := s.jwtService.Validate(in.Token)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "token is expired or invalid")
	}

	if claims, ok := token.Claims.(j.MapClaims); ok && token.Valid {
		// jwt numeric representation is always float64
		if userID, ok := claims["userID"].(float64); ok {
			return &pb.AuthenticateResponse{
				UserID: int64(userID),
			}, nil
		}
	}

	return nil, status.Error(codes.Internal, "failed to extract user ID from token")
}
