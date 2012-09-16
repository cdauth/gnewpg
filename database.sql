CREATE TABLE "keys" (
	"id" BIGINT PRIMARY KEY CHECK ("id" > 0), -- Long ID of the key
	"binary" bytea NOT NULL,
	"perm_idsearch" BOOLEAN NOT NULL, -- Key should be findable by searching for its ID
	"perm_searchengines" BOOLEAN NOT NULL, -- Key might be listed in search engines
	"expires" TIMESTAMP,
	"revoked" BOOLEAN NOT NULL
	-- "primary_identity" BIGINT NOT NULL REFERENCES "identities"("id"), -- Added later, table "identities" is not defined yet here
	-- "user" BIGINT REFERENCES "users"("id") -- Added later, table "users" is not defined yet here
);
	
CREATE TABLE "identities" (
	"id" BIGSERIAL PRIMARY KEY,
	"key" BIGINT NOT NULL REFERENCES "keys"("id"),
	"name" TEXT NOT NULL,
	"email" TEXT NOT NULL,
	"comment" TEXT NOT NULL,
	"revoked" BOOLEAN NOT NULL,
	"perm_public" BOOLEAN NOT NULL, -- Identity is visible to people who do not know about it yet
	"perm_namesearch" BOOLEAN NOT NULL, -- The key can be found by searching for the name stated in this identity
	"perm_emailsearch" BOOLEAN NOT NULL, -- The key can be found by searching for the e-mail address stated in this identity
	"email_blacklisted" TIMESTAMP -- If a date is set, the recipient of an e-mail verification mail stated that the key does not belong to them
);

CREATE TABLE "signatures" (
	"id" BIGSERIAL PRIMARY KEY,
	"identity" BIGINT NOT NULL REFERENCES "identities"("id"),
	"bykey" BIGINT CHECK ("bykey" > 0), -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL
);

CREATE TABLE "subkeys" (
	"id" BIGINT PRIMARY KEY CHECK ("id" > 0),
	"parentkey" BIGINT NOT NULL REFERENCES "keys"("id"),
	"expires" TIMESTAMP NOT NULL,
	"revoked" BOOLEAN NOT NULL
);



CREATE TABLE "users" (
	"name" TEXT PRIMARY KEY,
	"password" CHAR(64) NOT NULL,
	"email" TEXT,
	"openid" TEXT UNIQUE
);

CREATE TABLE "keyring" (
	"user" TEXT NOT NULL REFERENCES "users"("name"),
	"identity" BIGINT NOT NULL REFERENCES "identities"("id"),
	PRIMARY KEY ("user", "identity")
);

CREATE TABLE "email_verification" (
	"token" CHAR(32) PRIMARY KEY,
	"identity" BIGINT NOT NULL REFERENCES "identities"("identity"),
	"date" TIMESTAMP
);



CREATE TABLE "groups" (
	"id" BIGSERIAL PRIMARY KEY,
	"token" CHAR(64) UNIQUE,
	"title" TEXT,
	"perm_searchengines" BOOLEAN NOT NULL, -- Whether the group should be findable by search engines
	"perm_addkeys" BOOLEAN NOT NULL -- Whether all users should be allowed to add keys
);

CREATE TABLE "group_keyrings" (
	"group" BIGINT REFERENCES "groups"("id"),
	"identity" BIGINT REFERENCES "identities"("id"),
	PRIMARY KEY ("group", "identity")
);

CREATE TABLE "group_users" (
	"group" BIGINT REFERENCES "groups"("id"),
	"user" BIGINT REFERENCES "users"("id") ON UPDATE CASCADE,
	"perm_admin" BOOLEAN NOT NULL, -- Whether the user is allowed to change the group settings
	"perm_addkeys" BOOLEAN NOT NULL -- Whether the user is allowed to add keys to the group
);


CREATE TABLE "sessions" (
	"id" CHAR(64) PRIMARY KEY,
	"user" TEXT NOT NULL REFERENCES "users"("name") ON UPDATE CASCADE ON DELETE CASCADE,
	"last_access" TIMESTAMP NOT NULL
);

CREATE INDEX "sessions_time_idx" ON "sessions"("last_access");



ALTER TABLE "keys"
	ADD COLUMN "primary_identity" BIGINT NOT NULL REFERENCES "identities"("id"),
	ADD COLUMN "user" BIGINT REFERENCES "users"("id") ON UPDATE CASCADE ON DELETE SET DEFAULT;