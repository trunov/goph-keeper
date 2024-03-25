package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/trunov/goph-keeper/server/auth/internal/domain/models"
)

type jwtService struct {
	secret string
}

type JWTService interface {
	NewToken(user models.User, duration time.Duration) (string, error)
	Validate(tokenString string) (*jwt.Token, error)
}

func NewJWTService(secret string) JWTService {
	return &jwtService{
		secret: secret,
	}
}

func (s *jwtService) NewToken(user models.User, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["userID"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()

	tokenString, err := token.SignedString([]byte(s.secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *jwtService) Validate(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method in token")
		}
		return []byte(s.secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token, nil
}
