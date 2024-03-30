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

    if (db.countUsers() == 0){
        db.createUser("root","root","root");
        db.createRole("ROOT",LONG_LONG_MIN);
        db.assignUserRole("root","ROOT");
    }



    return 0;
}
