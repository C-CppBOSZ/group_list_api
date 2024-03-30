//
// Created by bogusz on 29.03.24.
//

#ifndef ROUTES_H
#define ROUTES_H

#include "crow.h"
#include "crow/middlewares/cors.h"
#include "jwt/jwt.hpp"


namespace routes{

static std::string tokenKey = "j4kUQYTuYiowYY92sU23Wuqu8y1TYo";

    struct AuthorizationMW : crow::ILocalMiddleware {
        struct context {
        };

        void before_handle(crow::request &req, crow::response &res, context &ctx) {
            std::string token = req.get_header_value("Authorization");
            try {
                auto dec_obj = jwt::decode(token, jwt::params::algorithms({"HS256"}), jwt::params::secret(tokenKey),
                                           jwt::params::verify(true));
                std::string value = dec_obj.payload().get_claim_value<std::string>("name");

                req.add_header("name", value);
            } catch (...) {
                res.code = 401;
                res.end();
            }
        }

        void after_handle(crow::request &req, crow::response &res, context &ctx) {
        }
    };


    typedef crow::App<crow::CORSHandler,AuthorizationMW> MyApp;

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
