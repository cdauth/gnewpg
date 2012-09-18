CREATE TABLE "keys" (
	"id" BIGINT PRIMARY KEY CHECK ("id" > 0), -- Long ID of the key
	"binary" bytea NOT NULL,
	"perm_idsearch" BOOLEAN NOT NULL, -- Key should be findable by searching for its ID
	"perm_searchengines" BOOLEAN NOT NULL, -- Key might be listed in search engines
	"expires" TIMESTAMP,
	"revokedby" BIGINT REFERENCES "keys_signatures"("id")
	-- "primary_identity" BIGINT NOT NULL REFERENCES "identities"("id"), -- Added later, table "identities" is not defined yet here
	-- "user" TEXT REFERENCES "users"("name") -- Added later, table "users" is not defined yet here
);

CREATE TABLE "keys_signatures" (
	"id" BIGSERIAL PRIMARY KEY,
	"key" BIGINT NOT NULL CHECK ("key" > 0),
	"issuer" BIGINT CHECK ("issuer" > 0), -- Long ID of the key that made the signature. Not a foreign key as the key might be a subkey or unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (0x19, 0x1F, 0x20)),
	"expires" TIMESTAMP,
	"revokedby" BIGINT REFERENCES "keys_signatures" ("id")
);
	
CREATE TABLE "keys_identities" (
	"id" BIGSERIAL PRIMARY KEY,
	"key" BIGINT NOT NULL REFERENCES "keys"("id"),
	"binary" BYTEA NOT NULL,
	"name" TEXT NOT NULL,
	"email" TEXT NOT NULL,
	"perm_public" BOOLEAN NOT NULL, -- Identity is visible to people who do not know about it yet
	"perm_namesearch" BOOLEAN NOT NULL, -- The key can be found by searching for the name stated in this identity
	"perm_emailsearch" BOOLEAN NOT NULL, -- The key can be found by searching for the e-mail address stated in this identity
	"email_blacklisted" TIMESTAMP, -- If a date is set, the recipient of an e-mail verification mail stated that the key does not belong to them
	"revokedby" BIGINT REFERENCES "keys_identities_signatures"("id")
);

CREATE TABLE "keys_identities_signatures" (
	"id" BIGSERIAL PRIMARY KEY,
	"identity" BIGINT NOT NULL REFERENCES "keys_identities"("id"),
	"issuer" BIGINT CHECK ("issuer" > 0), -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (0x10, 0x11, 0x12, 0x13, 0x30)),
	"expires" TIMESTAMP,
	"revokedby" BIGINT REFERENCES "keys_identities_signatures" ("id")
);

CREATE TABLE "keys_attributes" (
	"id" BIGSERIAL PRIMARY KEY,
	"key" BIGINT NOT NULL REFERENCES "keys"("id"),
	"binary" BYTEA NOT NULL,
	"perm_public" BOOLEAN NOT NULL, -- Identity is visible to people who do not know about it yet
	"revokedby" BIGINT REFERENCES "keys_attributes_signatures"("id")
);

CREATE TABLE "keys_attributes_signatures" (
	"id" BIGSERIAL PRIMARY KEY,
	"identity" BIGINT NOT NULL REFERENCES "keys_attributes"("id"),
	"issuer" BIGINT CHECK ("issuer" > 0), -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (0x10, 0x11, 0x12, 0x13, 0x30)),
	"expires" TIMESTAMP,
	"revokedby" BIGINT REFERENCES "keys_attributes_signatures" ("id")
);

CREATE TABLE "keys_subkeys" (
	"id" BIGINT PRIMARY KEY CHECK ("id" > 0),
	"parentkey" BIGINT NOT NULL REFERENCES "keys"("id"),
	"expires" TIMESTAMP NOT NULL,
	"revokedby" BIGINT REFERENCES "keys_subkeys_signatures"("id")
);

CREATE TABLE "keys_subkeys_signatures" (
	"id" BIGSERIAL PRIMARY KEY,
	"key" BIGINT NOT NULL CHECK ("key" > 0),
	"issuer" BIGINT CHECK ("issuer" > 0), -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (0x18, 0x28)),
	"expires" TIMESTAMP,
	"revoked" BOOLEAN NOT NULL,
	"revokedby" BIGINT REFERENCES "keys_subkeys_signatures" ("id")
);



CREATE TABLE "users" (
	"name" TEXT PRIMARY KEY,
	"password" CHAR(44) NOT NULL,
	"email" TEXT,
	"openid" TEXT UNIQUE,
	"secret" CHAR(44) NOT NULL UNIQUE -- A secret string for the personal keyserver URL
);

CREATE INDEX "users_lower_idx" ON "users" (LOWER("name"));

CREATE TABLE "keyring_identities" (
	"user" TEXT NOT NULL REFERENCES "users"("name"),
	"identity" BIGINT NOT NULL REFERENCES "keys_identities"("id"),
	PRIMARY KEY ("user", "identity")
);

CREATE TABLE "keyring_attributes" (
	"user" TEXT NOT NULL REFERENCES "users"("name"),
	"attribute" BIGINT NOT NULL REFERENCES "keys_attributes"("id"),
	PRIMARY KEY ("user", "attribute")
);

CREATE TABLE "email_verification" (
	"token" CHAR(44) PRIMARY KEY,
	"identity" BIGINT NOT NULL REFERENCES "keys_identities"("id"),
	"date" TIMESTAMP
);



CREATE TABLE "groups" (
	"id" BIGSERIAL PRIMARY KEY,
	"token" CHAR(44) UNIQUE,
	"title" TEXT,
	"perm_searchengines" BOOLEAN NOT NULL, -- Whether the group should be findable by search engines
	"perm_addkeys" BOOLEAN NOT NULL -- Whether all users should be allowed to add keys
);

CREATE TABLE "group_keyrings_identities" (
	"group" BIGINT REFERENCES "groups"("id"),
	"identity" BIGINT REFERENCES "keys_identities"("id"),
	PRIMARY KEY ("group", "identity")
);

CREATE TABLE "group_keyrings_attributes" (
	"group" BIGINT REFERENCES "groups"("id"),
	"attribute" BIGINT REFERENCES "keys_attributes"("id"),
	PRIMARY KEY ("group", "attribute")
);

CREATE TABLE "group_users" (
	"group" BIGINT REFERENCES "groups"("id"),
	"user" TEXT REFERENCES "users"("name") ON UPDATE CASCADE,
	"perm_admin" BOOLEAN NOT NULL, -- Whether the user is allowed to change the group settings
	"perm_addkeys" BOOLEAN NOT NULL -- Whether the user is allowed to add keys to the group
);


CREATE TABLE "sessions" (
	"id" CHAR(44) PRIMARY KEY,
	"user" TEXT NOT NULL REFERENCES "users"("name") ON UPDATE CASCADE ON DELETE CASCADE,
	"last_access" TIMESTAMP NOT NULL,
	"persistent" BOOLEAN
);

CREATE INDEX "sessions_time_idx" ON "sessions"("persistent", "last_access");



ALTER TABLE "keys"
	ADD COLUMN "primary_identity" BIGINT NOT NULL REFERENCES "keys_identities"("id"),
	ADD COLUMN "user" TEXT REFERENCES "users"("name") ON UPDATE CASCADE ON DELETE SET DEFAULT;