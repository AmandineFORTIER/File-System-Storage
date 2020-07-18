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
	char *zErrMsg = 0;
	int rc = sqlite3_open("database/users.db",&db);
	if(rc)
	{
		std::cout<<"Can't open database: "<<sqlite3_errmsg(db)<<"\n";
	} 
	else
	{
		std::cout<<"Open database successfully\n\n";
	}
	//std::string del = " DELETE FROM PWD8;";
	//rc = sqlite3_exec(db, del.c_str(), callback, (void*)data, &zErrMsg);
	std::string sql = " INSERT INTO user(username,password,grade) VALUES ('test','pass','Admin'); ";
	rc = sqlite3_exec(db,sql.c_str(),callback,0,&zErrMsg);
	if( rc!=SQLITE_OK )
	{
		std::cout<<"SQL error: "<<sqlite3_errmsg(db)<<"\n";
		sqlite3_free(zErrMsg);
	}
	std::cout<<"fin exec sqlite"<<std::endl;
	//sql = "SELECT * from PWD8;";
	//rc = sqlite3_exec(db, sql.c_str(), callback, (void*)data, &zErrMsg);
	//std::cout<<"fin exec affichage"<<std::endl;


	std::cout<<"After create table"<<std::endl;

	sqlite3_close(db);
}