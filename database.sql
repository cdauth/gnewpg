CREATE TABLE "keys" (
	"id" CHAR(16) PRIMARY KEY, -- Long ID of the key
	"binary" bytea NOT NULL,
	"date" TIMESTAMP NOT NULL,
	"perm_idsearch" BOOLEAN NOT NULL DEFAULT false, -- Key should be findable by searching for its ID
	"perm_searchengines" BOOLEAN NOT NULL DEFAULT false, -- Key might be listed in search engines
	"expires" TIMESTAMP DEFAULT NULL,
	"revokedby" CHAR(27) DEFAULT NULL -- This can reference all three signature tables
	-- "primary_identity" TEXT DEFAULT NULL, -- Added later, table "identities" is not defined yet here
	-- "user" TEXT REFERENCES "users"("name") DEFAULT NULL ON UPDATE CASCADE ON DELETE SET DEFAULT; -- Added later, table "users" is not defined yet here
);

CREATE TABLE "keys_signatures" (
	"id" CHAR(27) PRIMARY KEY,
	"key" CHAR(16) NOT NULL REFERENCES "keys"("id"),
	"issuer" CHAR(16) NOT NULL, -- Long ID of the key that made the signature. Not a foreign key as the key might be a subkey or unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL DEFAULT false,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (25, 31, 32, 24, 40, 48)), -- 0x19, 0x1F, 0x20, 0x18, 0x28, 0x30
	"expires" TIMESTAMP,
	"revokedby" CHAR(27) REFERENCES "keys_signatures" ("id") DEFAULT NULL
);

CREATE INDEX "keys_signatures_key_idx" ON "keys_signatures" ("key");
CREATE INDEX "keys_signatures_issuer_idx" ON "keys_signatures" ("issuer");

CREATE VIEW "keys_subkeys" AS SELECT DISTINCT
	"keys"."id" AS "id",
	"keys"."binary" AS "binary",
	"keys_signatures"."issuer" AS "parentkey",
	"keys_signatures"."expires" AS "expires",
	"keys_signatures"."revokedby" AS "revokedby"
	FROM "keys", "keys_signatures" WHERE "keys_signatures"."key" = "keys"."id" AND "keys_signatures"."verified" = true AND "keys_signatures"."sigtype" = 24 -- 0x18
;

-----------------------------------------------------
	
CREATE TABLE "keys_identities" (
	"id" TEXT NOT NULL, -- The ID is simply the text of the identity, thus only unique per key
	"key" CHAR(16) NOT NULL REFERENCES "keys"("id"),
	"name" TEXT NOT NULL,
	"email" TEXT NOT NULL,
	"perm_public" BOOLEAN NOT NULL DEFAULT false, -- Identity is visible to people who do not know about it yet
	"perm_namesearch" BOOLEAN NOT NULL DEFAULT false, -- The key can be found by searching for the name stated in this identity
	"perm_emailsearch" BOOLEAN NOT NULL DEFAULT false, -- The key can be found by searching for the e-mail address stated in this identity
	"email_blacklisted" TIMESTAMP DEFAULT NULL, -- If a date is set, the recipient of an e-mail verification mail stated that the key does not belong to them

	PRIMARY KEY("id", "key")
);

CREATE TABLE "keys_identities_signatures" (
	"id" CHAR(27) PRIMARY KEY,
	"identity" TEXT NOT NULL,
	"key" CHAR(16) NOT NULL,
	"issuer" CHAR(16) NOT NULL, -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL DEFAULT false,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (16, 17, 18, 19, 48)), --0x10, 0x11, 0x12, 0x13, 0x30
	"expires" TIMESTAMP,
	"revokedby" CHAR(27) REFERENCES "keys_identities_signatures" ("id") DEFAULT NULL,

	FOREIGN KEY ("identity", "key") REFERENCES "keys_identities" ( "id", "key" )
);

CREATE INDEX "keys_identities_signatures_key_idx" ON "keys_identities_signatures" ("key");
CREATE INDEX "keys_identities_signatures_issuer_idx" ON "keys_identities_signatures" ("issuer");

-----------------------------------------------------

CREATE TABLE "keys_attributes" (
	"id" CHAR(27) NOT NULL, -- The ID is the sha1sum of the content, thus only unique per key
	"key" CHAR(16) NOT NULL REFERENCES "keys"("id"),
	"binary" BYTEA NOT NULL,
	"perm_public" BOOLEAN NOT NULL DEFAULT false, -- Identity is visible to people who do not know about it yet

	PRIMARY KEY("id", "key")
);

CREATE TABLE "keys_attributes_signatures" (
	"id" CHAR(27) PRIMARY KEY,
	"attribute" CHAR(27) NOT NULL,
	"key" CHAR(16) NOT NULL,
	"issuer" CHAR(16) NOT NULL, -- Long ID of the key that made the signature. Not a foreign key as the key might be unknown
	"date" TIMESTAMP NOT NULL,
	"binary" bytea NOT NULL,
	"verified" BOOLEAN NOT NULL DEFAULT false,
	"sigtype" SMALLINT NOT NULL CHECK ("sigtype" IN (16, 17, 18, 19, 48)), --0x10, 0x11, 0x12, 0x13, 0x30
	"expires" TIMESTAMP,
	"revokedby" CHAR(27) REFERENCES "keys_attributes_signatures" ("id") DEFAULT NULL,
	
	FOREIGN KEY ("attribute", "key") REFERENCES "keys_attributes"("id", "key")
);

CREATE INDEX "keys_identities_attributes_key_idx" ON "keys_attributes_signatures" ("key");
CREATE INDEX "keys_attributes_attributes_issuer_idx" ON "keys_attributes_signatures" ("issuer");

-----------------------------------------------------

CREATE VIEW "keys_signatures_all" AS
	      SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby", 'keys_signatures' AS "table", NULL AS "objectcol" FROM "keys_signatures"
	UNION SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby", 'keys_identities_signatures' AS "table", 'identity' AS "objectcol" FROM "keys_identities_signatures"
	UNION SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby", 'keys_attributes_signatures' AS "table", 'attribute' AS "objectcol" FROM "keys_attributes_signatures"
;


--===================================================
--===================================================
--===================================================


CREATE TABLE "users" (
	"id" TEXT PRIMARY KEY,
	"password" CHAR(43) NOT NULL,
	"email" TEXT,
	"openid" TEXT UNIQUE,
	"secret" CHAR(43) NOT NULL UNIQUE -- A secret string for the personal keyserver URL
);

CREATE INDEX "users_lower_idx" ON "users" (LOWER("id"));

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
	"date" TIMESTAMP,
	FOREIGN KEY ( "identity", "identityKey" ) REFERENCES "keys_identities" ( "id", "key" )
);


--===================================================
--===================================================
--===================================================


CREATE TABLE "groups" (
	"id" BIGSERIAL PRIMARY KEY,
	"token" CHAR(43) UNIQUE,
	"title" TEXT,
	"perm_searchengines" BOOLEAN NOT NULL, -- Whether the group should be findable by search engines
	"perm_addkeys" BOOLEAN NOT NULL -- Whether all users should be allowed to add keys
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


--===================================================
--===================================================
--===================================================


CREATE TABLE "sessions" (
	"id" CHAR(43) PRIMARY KEY,
	"user" TEXT NOT NULL REFERENCES "users"("id") ON UPDATE CASCADE ON DELETE CASCADE,
	"last_access" TIMESTAMP NOT NULL,
	"persistent" BOOLEAN
);

CREATE INDEX "sessions_time_idx" ON "sessions"("persistent", "last_access");


--===================================================
--===================================================
--===================================================


ALTER TABLE "keys"
	ADD COLUMN "primary_identity" TEXT DEFAULT NULL,
	ADD COLUMN "user" TEXT DEFAULT NULL REFERENCES "users"("id") ON UPDATE CASCADE ON DELETE SET DEFAULT,
	ADD FOREIGN KEY ("primary_identity", "id") REFERENCES "keys_identities" ("id", "key");