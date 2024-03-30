//
// Created by bogusz on 29.03.24.
//

#ifndef ROUTES_H
#define ROUTES_H

#include "crow.h"
#include "crow/middlewares/cors.h"

namespace routes{

typedef crow::App<crow::CORSHandler> MyApp;

static MyApp app;

//inline MyApp& get_app() {
//    static MyApp app;
//    auto& cors = app.get_middleware<crow::CORSHandler>();
//
//    cors
//    .global()
//    .methods("POST"_method,"PUT"_method,"GET"_method,"DELETE"_method);
//
//    return app;
//}

}



#endif //ROUTES_H
