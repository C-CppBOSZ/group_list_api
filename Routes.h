//
// Created by bogusz on 29.03.24.
//

#ifndef ROUTES_H
#define ROUTES_H

#include <random>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <string>

#include "crow.h"
#include "crow/middlewares/cors.h"
#include "jwt/jwt.hpp"
#include "service/base/DBBase.h"


namespace routes{

static std::string tokenKey = "j4kUQYTuYiowYY92sU23Wuqu8y1TYo";

    struct AuthorizationMW : crow::ILocalMiddleware {
        struct context {
            std::string name;
        };

        void before_handle(crow::request &req, crow::response &res, context &ctx) {
            std::string token = req.get_header_value("Authorization");
            try {
                auto dec_obj = jwt::decode(token, jwt::params::algorithms({"HS256"}), jwt::params::secret(tokenKey),
                                           jwt::params::verify(true));
                std::string value = dec_obj.payload().get_claim_value<std::string>("name");

//                req.add_header("name", value);
                ctx.name = value;
            }catch (const jwt::TokenExpiredError& e) {
                res.code = 403;
                res.body = "TokenExpiredError";
                res.end();
            }
            catch (...) {
                res.code = 403;
                res.end();
            }
        }

        void after_handle(crow::request &req, crow::response &res, context &ctx) {
        }
    };


    typedef crow::App<crow::CORSHandler,AuthorizationMW> MyApp;

    static MyApp app;


//        /register - Ścieżka do rejestracji nowego użytkownika.
//        /login - Ścieżka do logowania użytkownika i generowania tokena JWT.

    std::string generateSalt(const std::size_t &length) {
        const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

        std::string random_string;

        for (std::size_t i = 0; i < length; ++i)
        {
            random_string += CHARACTERS[distribution(generator)];
        }
        return random_string;
    }

    std::string generateHashedPassword(const std::string& password, const std::string& salt) {
        std::string str = password + salt;

        unsigned char hash[MD5_DIGEST_LENGTH];

        MD5_CTX md5;
        MD5_Init(&md5);
        MD5_Update(&md5, str.c_str(), str.size());
        MD5_Final(hash, &md5);

        std::stringstream ss;

        for(unsigned char i : hash){
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( i );
        }
        return ss.str();
    }

    void authorizationRoutes(DB::UserCRUDBase& user){

        CROW_ROUTE(app,"/user/register").methods("POST"_method)
                ([&](const crow::request &req) {
                    auto x = crow::json::load(req.body);
                    if (!x && !x.has("name") && !x.has("password"))
                        return crow::response(400);
                    std::string salt = generateSalt(50);
                    const std::string &password = generateHashedPassword(x["password"].s(), salt);
                    user.createUser(x["name"].s(), password, salt);
                    return crow::response(200);
                });

        CROW_ROUTE(app, "/user/login").methods("POST"_method)
                ([&](const crow::request &req) {
                    using namespace std::chrono_literals;
                    auto x = crow::json::load(req.body);
                    if (!x && !x.has("name") && !x.has("password"))
                        return crow::response(400);
                    std::string name = x["name"].s();
                    const std::tuple<int, std::string, std::string, std::string> &readUser = user.readUser(name);
                    if (std::get<2>(readUser) == generateHashedPassword(x["password"].s(),std::get<3>(readUser)))
                        return crow::response(jwt::jwt_object{
                                jwt::params::algorithm("HS256"), jwt::params::payload({{"name", name}}),
                                jwt::params::secret(tokenKey)
                        }.add_claim("exp", std::chrono::system_clock::now() + 4h)
                        .signature());
                    else
                        return crow::response(401);
                });

        CROW_ROUTE(app, "/user/auth").methods("POST"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request &req) {

                    auto ctx = app.get_context<AuthorizationMW>(req);

                    return crow::response(ctx.name);
                });

    }

    void usersRoutes(DB::UserCRUDBase& user,DB::UserRolesBase& userRoles){

        CROW_ROUTE(app, "/user/delete/<string>").methods("DELETE"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request& req, std::string name) {
                    auto ctx = app.get_context<AuthorizationMW>(req);
                    long permissions = userRoles.getUserPermissions(ctx.name);
                    if ((permissions & DB::RolePermission::UserD) == 0)
                        return crow::response(403);
                    user.deleteUser(name);
                    return crow::response(200);
                });



    }

    void selfRoutes(DB::UserCRUDBase& user,DB::UserRolesBase& userRoles){

        CROW_ROUTE(app, "/self/delete").methods("DELETE"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request& req) {
                    auto ctx = app.get_context<AuthorizationMW>(req);
                    user.deleteUser(ctx.name);
                    return crow::response(200);
                });

    }

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
