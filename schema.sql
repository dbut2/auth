CREATE TABLE Users (
    ID SERIAL UNIQUE NOT NULL PRIMARY KEY
);

CREATE TABLE UserTokens (
    Provider VARCHAR(255) NOT NULL,
    ProviderIdentity TEXT NOT NULL,
    UserID INTEGER REFERENCES Users(ID) NOT NULL,
    Token TEXT,
    PRIMARY KEY (Provider, ProviderIdentity)
);

CREATE Table Codes (
    Code TEXT UNIQUE NOT NULL,
    UserID INTEGER REFERENCES Users(ID) NOT NULL
);
