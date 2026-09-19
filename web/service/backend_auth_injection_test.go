package service

import (
	"errors"
	"testing"

	"github.com/djylb/nps/lib/credential"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/servercfg"
)

func TestDefaultAuthServiceUsesInjectedRepository(t *testing.T) {
	service := DefaultAuthService{
		ConfigProvider: func() *servercfg.Snapshot {
			return &servercfg.Snapshot{
				Feature: servercfg.FeatureConfig{AllowUserLogin: true},
			}
		},
		Backend: Backend{
			Repository: stubRepository{
				getUserByUsername: func(username string) (*file.User, error) {
					if username == "demo" {
						return &file.User{Id: 3, Username: username, Password: "secret", Status: 1, TotalFlow: &file.Flow{}}, nil
					}
					return nil, nil
				},
				rangeClients: func(fn func(*file.Client) bool) {
					fn(&file.Client{
						Id:     42,
						Status: true,
						UserId: 3,
					})
				},
			},
		},
	}

	identity, err := service.Authenticate(AuthenticateInput{
		Username: "demo",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if identity == nil || len(identity.ClientIDs) != 1 || identity.ClientIDs[0] != 42 {
		t.Fatalf("Authenticate() = %+v, want injected repository-backed identity", identity)
	}
}

func TestDefaultAuthServiceRegisterUserUsesInjectedRepository(t *testing.T) {
	var created struct {
		ID       int
		Username string
		Password string
	}
	var createdSet bool
	service := DefaultAuthService{
		ConfigProvider: func() *servercfg.Snapshot {
			return &servercfg.Snapshot{
				Web: servercfg.WebConfig{Username: "admin"},
			}
		},
		Backend: Backend{
			Repository: stubRepository{
				nextUserID: func() int { return 11 },
				createUser: func(user *file.User) error {
					if user.Id != 11 || user.Username != "demo" {
						t.Fatalf("CreateUser() got %+v", user)
					}
					if !credential.IsPasswordHash(user.Password) {
						t.Fatalf("CreateUser() stored plaintext password, want Argon2id hash: %q", user.Password)
					}
					match, _, err := credential.VerifyPassword(user.Password, "secret")
					if err != nil || !match {
						t.Fatalf("CreateUser() stored hash does not verify against password: match=%v err=%v", match, err)
					}
					return nil
				},
				nextClientID: func() int { return 73 },
				createClient: func(client *file.Client) error {
					created = struct {
						ID       int
						Username string
						Password string
					}{
						ID: client.Id,
					}
					createdSet = true
					return nil
				},
			},
		},
	}

	result, err := service.RegisterUser(RegisterUserInput{
		Username: "demo",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("RegisterUser() error = %v", err)
	}
	if !createdSet || created.ID != 73 || created.Username != "" || created.Password != "" {
		t.Fatalf("RegisterUser() created client = %+v, want injected repository-backed client", created)
	}
	if result == nil || len(result.ClientIDs) != 1 || result.ClientIDs[0] != 73 {
		t.Fatalf("RegisterUser() = %+v, want client id 73", result)
	}
}

func TestDefaultAuthServiceRegisterUserRollsBackUserWhenClientCreateFails(t *testing.T) {
	var deletedUserID int
	service := DefaultAuthService{
		ConfigProvider: func() *servercfg.Snapshot {
			return &servercfg.Snapshot{
				Web: servercfg.WebConfig{Username: "admin"},
			}
		},
		Backend: Backend{
			Repository: stubRepository{
				nextUserID:   func() int { return 11 },
				nextClientID: func() int { return 73 },
				createUser: func(user *file.User) error {
					if user.Id != 11 {
						t.Fatalf("CreateUser() got %+v", user)
					}
					return nil
				},
				createClient: func(*file.Client) error {
					return errors.New("create client failed")
				},
				deleteUser: func(id int) error {
					deletedUserID = id
					return nil
				},
			},
		},
	}

	result, err := service.RegisterUser(RegisterUserInput{
		Username: "demo",
		Password: "secret",
	})
	if err == nil || err.Error() != "create client failed" {
		t.Fatalf("RegisterUser() error = %v, want create client failed", err)
	}
	if result != nil {
		t.Fatalf("RegisterUser() result = %+v, want nil on failure", result)
	}
	if deletedUserID != 11 {
		t.Fatalf("RegisterUser() deleted user id = %d, want 11", deletedUserID)
	}
}
