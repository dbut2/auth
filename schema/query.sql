-- name: GetUser :one

SELECT u.ID FROM Users u

INNER JOIN UserTokens ut on ut.UserID = u.ID

WHERE ut.Provider = $1
  AND ut.ProviderIdentity = $2

LIMIT 1;

-- name: CreateUser :one

INSERT INTO Users DEFAULT VALUES RETURNING ID;

-- name: GetToken :one

SELECT Token FROM UserTokens ut

WHERE ut.Provider = $1
  AND ut.ProviderIdentity = $2

LIMIT 1;

-- name: StoreToken :exec

INSERT INTO UserTokens (Provider, ProviderIdentity, UserID, Token)

VALUES ($1, $2, $3, $4)

ON CONFLICT (Provider, ProviderIdentity)
DO UPDATE SET Token = $4;

-- name: GetCodeUser :one

SELECT u.ID FROM Users u

INNER JOIN Codes c on c.UserID = u.ID

WHERE c.Code = $1

LIMIT 1;

-- name: StoreCode :exec

INSERT INTO Codes (Code, UserID) VALUES ($1, $2);
