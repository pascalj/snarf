CREATE TABLE "server_state" (
	"id"	INTEGER,
	"paseto_keypair"	BLOB,
	"cache_keypair"	BLOB,
	"initialized"	INTEGER NOT NULL DEFAULT 0 CHECK("initialized" IN (0, 1)),
	"cache_name"	TEXT DEFAULT 'snarf',
	PRIMARY KEY("id")
)
