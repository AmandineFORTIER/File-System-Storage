#include "sqlite_files/sqlite3.h"
#include <iostream> 
#include <cstring>
/**
 * https://gist.github.com/enile8/2424514
 */
static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
	int i;
	for(i=0; i<argc; i++)
	{
		std::cout<<azColName[i]<<" = " << (argv[i] ? argv[i] : "NULL")<<"\n";
	}
	std::cout<<"\n";
	return 0;
}

int main()
{
	sqlite3 *db;
	sqlite3_stmt* stmt;
	char *zErrMsg = 0;
	int rc = sqlite3_open("database/users.db",&db);
	if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

	char sql[] = "INSERT INTO user(username, password, grade) VALUES (?, ?, ?)";
	rc = sqlite3_prepare_v2(db,sql,-1, &stmt,0);
	if (rc != SQLITE_OK) 
	{
		fprintf(stderr, "Can't prepare select statment %s (%i): %s\n", sql, rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	std::string username = "Amandine";
	std::string password = "nyhtbgrvfed7642";
	std::string grade = "Administrateur";
	rc = sqlite3_bind_text(stmt, 1, username.c_str() ,sizeof(username),NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	rc = sqlite3_bind_text(stmt, 2, password.c_str() ,sizeof(password),NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	rc = sqlite3_bind_text(stmt, 3, grade.c_str() ,sizeof(grade),NULL);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "Error binding value in insert (%i): %s\n", rc, sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	
	rc = sqlite3_step(stmt);
	if(rc != SQLITE_DONE) {
		fprintf(stderr, "insert statement didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
	} else {
		printf("INSERT completed\n\n");
	}
	rc = sqlite3_clear_bindings(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "clear bindings didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
	}

    rc = sqlite3_reset(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "reset didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
	}

	rc = sqlite3_finalize(stmt);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "finalize didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
	}
	
	rc = sqlite3_close(db);
	if(rc != SQLITE_OK) {
		fprintf(stderr, "close didn't return DONE (%i): %s\n", rc, sqlite3_errmsg(db));
	}
}