#include <iostream>


#include "crow.h"
#include "crow/middlewares/cors.h"
#include "crow/websocket.h"

#include "Routes.h"
#include "service/DBService.h"


int main() {
//    auto& app = routes::get_app();

    auto& cors = routes::app.get_middleware<crow::CORSHandler>();

    cors
    .global()
    .methods("POST"_method,"PUT"_method,"GET"_method,"DELETE"_method);

    DB::DBService db("dbname=group user=postgres password=postgres host=localhost port=5324");

    const DB::resDB<int> &users = db.countUsers();
    if (!users.ok){
        std::cerr << users.msg;
        return 1;
    }

    if (*users.get == 0){
        const std::string &salt = routes::generateSalt(50);
        db.createUser("root",routes::generateHashedPassword("root",salt),salt);
        db.createRole("ROOT",0x1111111111111111111111111111111111111111111111111111111111111111);
        db.assignUserRole("root","ROOT");
    }

    routes::authorizationRoutes(db);
    routes::usersRoutes(db,db);
    routes::selfRoutes(db,db);


    routes::app.port(2050).multithreaded().run();

    return 0;
}
