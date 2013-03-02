CREATE TABLE "users" (
	"id" TEXT PRIMARY KEY,
	"password" CHAR(43) NOT NULL,
	"email" TEXT,
	"mainkey" CHAR(16),
	"openid" TEXT UNIQUE,
	"secret" CHAR(43) NOT NULL UNIQUE, -- A secret string for the personal keyserver URL
	"locale" TEXT NOT NULL
);

CREATE INDEX "users_lower_idx" ON "users" (LOWER("id"));

CREATE TABLE "users_keyrings_keys" (
	"user" TEXT REFERENCES "users"("id"),
	"key" CHAR(16) REFERENCES "keys"("id"),
	PRIMARY KEY("user", "key")
);

CREATE VIEW "users_keyrings_keys_with_keys" AS
	SELECT "keys"."id" AS "id", "keys"."fingerprint" AS "fingerprint", "keys"."binary" AS "binary", "keys"."date" AS "date",
		"keys"."expires" AS "expires", "keys"."revoked" AS "revoked", "keys"."primary_identity" AS "primary_identity",
		"users_keyrings_keys"."user" AS "user"
	FROM "keys", "users_keyrings_keys" WHERE "keys"."id" = "users_keyrings_keys"."key";

CREATE TABLE "users_keyrings_identities" (
	"user" TEXT REFERENCES "users"("id"),
	"identity" TEXT,
	"identityKey" CHAR(16),
	PRIMARY KEY ( "user", "identity", "identityKey" ),
	FOREIGN KEY ( "identity", "identityKey" ) REFERENCES "keys_identities" ( "id", "key" )
);

CREATE TABLE "users_keyrings_attributes" (
	"user" TEXT REFERENCES "users"("id"),
	"attribute" CHAR(27),
	"attributeKey" CHAR(16),
	PRIMARY KEY ( "user", "attribute", "attributeKey" ),
	FOREIGN KEY ( "attribute", "attributeKey" ) REFERENCES "keys_attributes" ( "id", "key" )
);

CREATE TABLE "users_email_verification" (
	"token" CHAR(43) PRIMARY KEY,
	"identity" TEXT NOT NULL,
	"identityKey" CHAR(16) NOT NULL,
	"date" TIMESTAMP WITH TIME ZONE,
	FOREIGN KEY ( "identity", "identityKey" ) REFERENCES "keys_identities" ( "id", "key" )
);

CREATE TABLE "users_ownership_verification" (
	"token" CHAR(43) NOT NULL,
	"user" TEXT NOT NULL REFERENCES "users"("id"),
	"key" TEXT NOT NULL REFERENCES "keys" ( "id" ),
	"date" TIMESTAMP WITH TIME ZONE NOT NULL
);


-----------------------------------------------------
-----------------------------------------------------
-----------------------------------------------------


CREATE TABLE "groups" (
	"id" BIGSERIAL PRIMARY KEY,
	"token" CHAR(43) UNIQUE,
	"title" TEXT,
	"perm_searchengines" BOOLEAN NOT NULL, -- Whether the group should be findable by search engines
	"perm_addkeys" BOOLEAN NOT NULL -- Whether all users should be allowed to add keys
);

CREATE TABLE "groups_keyrings_keys" (
	"group" BIGINT REFERENCES "groups"("id"),
	"key" CHAR(16) REFERENCES "keys"("id"),
	PRIMARY KEY("group", "key")
);

CREATE TABLE "groups_keyrings_identities" (
	"group" BIGINT REFERENCES "groups"("id"),
	"identity" TEXT,
	"identityKey" CHAR(16),
	PRIMARY KEY ("group", "identity", "identityKey" ),
	FOREIGN KEY ( "identity", "identityKey" ) REFERENCES "keys_identities" ( "id", "key" )
);

CREATE TABLE "groups_keyrings_attributes" (
	"group" BIGINT REFERENCES "groups"("id"),
	"attribute" CHAR(27),
	"attributeKey" CHAR(16),
	PRIMARY KEY ("group", "attribute", "attributeKey" ),
	FOREIGN KEY ( "attribute", "attributeKey" ) REFERENCES "keys_attributes" ( "id", "key" )
);

CREATE TABLE "groups_users" (
	"group" BIGINT REFERENCES "groups"("id"),
	"user" TEXT REFERENCES "users"("id") ON UPDATE CASCADE,
	"perm_admin" BOOLEAN NOT NULL, -- Whether the user is allowed to change the group settings
	"perm_addkeys" BOOLEAN NOT NULL -- Whether the user is allowed to add keys to the group
);

CREATE VIEW "users_keyrings_with_groups_keys" AS
	SELECT "user", "key" FROM "users_keyrings_keys"
	UNION SELECT "users"."id" AS "user", "groups_keyrings_keys"."key" AS "key"
		FROM "users", "groups_users", "groups_keyrings_keys"
		WHERE "users"."id" = "groups_users"."user" AND "groups_users"."group" = "groups_keyrings_keys"."group";

CREATE VIEW "users_keyrings_with_groups_identities" AS
	SELECT "user", "identity", "identityKey" FROM "users_keyrings_identities"
	UNION SELECT "users"."id" AS "user", "groups_keyrings_identities"."identity" AS "identity", "groups_keyrings_identities"."identityKey" AS "identityKey"
		FROM "users", "groups_users", "groups_keyrings_identities"
		WHERE "users"."id" = "groups_users"."user" AND "groups_users"."group" = "groups_keyrings_identities"."group";

CREATE VIEW "users_keyrings_with_groups_attributes" AS
	SELECT "user", "attribute", "attributeKey" FROM "users_keyrings_attributes"
	UNION SELECT "users"."id" AS "user", "groups_keyrings_attributes"."attribute" AS "attribute", "groups_keyrings_attributes"."attributeKey" AS "attributeKey"
		FROM "users", "groups_users", "groups_keyrings_attributes"
		WHERE "users"."id" = "groups_users"."user" AND "groups_users"."group" = "groups_keyrings_attributes"."group";


-----------------------------------------------------
-----------------------------------------------------
-----------------------------------------------------


CREATE TABLE "sessions" (
	"id" CHAR(43) PRIMARY KEY,
	"user" TEXT NOT NULL REFERENCES "users"("id") ON UPDATE CASCADE ON DELETE CASCADE,
	"last_access" TIMESTAMP WITH TIME ZONE NOT NULL,
	"persistent" BOOLEAN
);

CREATE INDEX "sessions_time_idx" ON "sessions"("persistent", "last_access");


-----------------------------------------------------
-----------------------------------------------------
-----------------------------------------------------


CREATE TABLE "keys_settings" (
	"key" CHAR(16) REFERENCES "keys"("id") PRIMARY KEY,

	"user" TEXT REFERENCES "users"("id") ON UPDATE CASCADE ON DELETE CASCADE,
	"perm_idsearch" BOOLEAN NOT NULL DEFAULT false, -- Key should be findable by searching for its ID
	"perm_searchengines" BOOLEAN NOT NULL DEFAULT false -- Key might be listed in search engines
);

CREATE TABLE "keys_identities_settings" (
	"key" CHAR(16),
	"id" TEXT,

	"perm_public" BOOLEAN NOT NULL DEFAULT false, -- Identity is visible to people who do not know about it yet
	"perm_namesearch" BOOLEAN NOT NULL DEFAULT false, -- The key can be found by searching for the name stated in this identity
	"perm_emailsearch" BOOLEAN NOT NULL DEFAULT false, -- The key can be found by searching for the e-mail address stated in this identity
	"email_blacklisted" TIMESTAMP WITH TIME ZONE DEFAULT NULL, -- If a date is set, the recipient of an e-mail verification mail stated that the key does not belong to them

	PRIMARY KEY("key", "id")
);

CREATE TABLE "keys_attributes_settings" (
	"key" CHAR(16),
	"id" CHAR(27),

	"perm_public" BOOLEAN NOT NULL DEFAULT false, -- Identity is visible to people who do not know about it yet

	PRIMARY KEY("key", "id")
);