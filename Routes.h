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


namespace routes {

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
            } catch (const jwt::TokenExpiredError &e) {
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


    typedef crow::App<crow::CORSHandler, AuthorizationMW> MyApp;

    static MyApp app;


//        /register - Ścieżka do rejestracji nowego użytkownika.
//        /login - Ścieżka do logowania użytkownika i generowania tokena JWT.

    std::string generateSalt(const std::size_t &length) {
        const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

        std::string random_string;

        for (std::size_t i = 0; i < length; ++i) {
            random_string += CHARACTERS[distribution(generator)];
        }
        return random_string;
    }

    std::string generateHashedPassword(const std::string &password, const std::string &salt) {
        std::string str = password + salt;

        unsigned char hash[MD5_DIGEST_LENGTH];

        MD5_CTX md5;
        MD5_Init(&md5);
        MD5_Update(&md5, str.c_str(), str.size());
        MD5_Final(hash, &md5);

        std::stringstream ss;

        for (unsigned char i: hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( i );
        }
        return ss.str();
    }

    std::tuple<bool, crow::response> checkPermissions(DB::UserRolesBase &userRoles,const AuthorizationMW::context& ctx,long mask) {
        const DB::resDB<long> &resDb = userRoles.getUserPermissions(ctx.name);
        if (!resDb.ok) {
            return std::make_tuple(false, crow::response(400, resDb.msg));
        }
        long permissions = *resDb.get;
        if ((permissions & mask) == 0)
            return std::make_tuple(false, crow::response(403));
        return std::make_tuple(true, crow::response(200));
    }

    void authorizationRoutes(DB::UserCRUDBase &user) {

        CROW_ROUTE(app, "/user/register").methods("POST"_method)
                ([&](const crow::request &req) {
                    auto x = crow::json::load(req.body);
                    if (!x && !x.has("name") && !x.has("password"))
                        return crow::response(400);
                    std::string salt = generateSalt(50);
                    const std::string &password = generateHashedPassword(x["password"].s(), salt);
                    const DB::resDB<void> &resDb = user.createUser(x["name"].s(), password, salt);
                    if (!resDb.ok)
                        return crow::response(400, resDb.msg);
                    return crow::response(200);
                });

        CROW_ROUTE(app, "/user/login").methods("POST"_method)
                ([&](const crow::request &req) {
                    using namespace std::chrono_literals;
                    auto x = crow::json::load(req.body);
                    if (!x && !x.has("name") && !x.has("password"))
                        return crow::response(400);
                    std::string name = x["name"].s();
                    const auto &resDb = user.readUser(name);
                    if (!resDb.ok) {
                        return crow::response(400, resDb.msg);
                    }
                    const std::tuple<int, std::string, std::string, std::string> &readUser = *resDb.get;
                    if (std::get<2>(readUser) == generateHashedPassword(x["password"].s(), std::get<3>(readUser)))
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

    void usersRoutes(DB::UserCRUDBase &user, DB::UserRolesBase &userRoles) {

        CROW_ROUTE(app, "/user/all").methods("GET"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request &req) {

                    auto ctx = app.get_context<AuthorizationMW>(req);
                    std::tuple<bool, crow::response> tuple = checkPermissions(userRoles, ctx,DB::RolePermission::UserR);
                    if (!std::get<0>(tuple))
                        return std::move(std::get<1>(tuple));

                    DB::UserSortBy sort = DB::UserSortBy::None;
                    try {
                        std::string sort_params = req.url_params.get("UserSortBy");
                        if (!sort_params.empty()) {
                            if (sort_params == "ID")
                                sort = DB::UserSortBy::ID;
                            if (sort_params == "NAME")
                                sort = DB::UserSortBy::Name;
                        }
                    } catch (const std::exception &e) {

                    }

                    DB::SortOrder sortOrder = DB::SortOrder::Ascending;

                    try {
                        std::string sortOrder_params = req.url_params.get("SortOrder");
                        if (!sortOrder_params.empty()) {
                            if (sortOrder_params == "ASC")
                                sortOrder = DB::SortOrder::Ascending;
                            if (sortOrder_params == "DES")
                                sortOrder = DB::SortOrder::Descending;
                        }
                    } catch (const std::exception &e) {

                    }

                    int pageSize = -1, pageNumber = 1;

                    try {
                        std::string pageSize_params = req.url_params.get("PageSize");
                        std::string pageNumber_params = req.url_params.get("PageNumber");

                        if (!pageSize_params.empty() && !pageNumber_params.empty()) {

                                pageSize = std::stoi(pageSize_params);
                                pageNumber = std::stoi(pageNumber_params);

                        }
                    } catch (const std::exception &e) {
                        pageSize = -1;
                        pageNumber = 1;
                    }

                    std::vector<std::tuple<int, std::string>> users;
                    {
                        const auto &resDb = user.readAllUsers(sort, sortOrder, pageSize, pageNumber);
                        if (!resDb.ok) {
                            return crow::response(400, resDb.msg);
                        }
                        users = *resDb.get;
                    }
                    std::vector<crow::json::wvalue> vector_of_wvalue = {};
                    for (const auto &item: users) {
                        vector_of_wvalue.push_back({{"name", std::get<1>(item)}});
                    }

                    // TODO dodać do final pole z ilością elementów lub stron -- user.countUsers()
                    crow::json::wvalue final = vector_of_wvalue;
                    return crow::response(std::move(final));
                });


        CROW_ROUTE(app, "/user/delete/<string>").methods("DELETE"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request &req, std::string name) {
                    auto ctx = app.get_context<AuthorizationMW>(req);
                    std::tuple<bool, crow::response> tuple = checkPermissions(userRoles, ctx,
                                                                                     DB::RolePermission::UserD);
                    if (!std::get<0>(tuple))
                        return std::move(std::get<1>(tuple));
                    // TODO usunąć usera z wszystkich relacji
                    user.deleteUser(name);
                    return crow::response(200);
                });

        CROW_ROUTE(app, "/user/update").methods("PUT"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request &req) {
                    auto ctx = app.get_context<AuthorizationMW>(req);
                    std::tuple<bool, crow::response> tuple = checkPermissions(userRoles, ctx,
                                                                              DB::RolePermission::UserU);
                    if (!std::get<0>(tuple))
                        return std::move(std::get<1>(tuple));

                    auto x = crow::json::load(req.body);

                    if (!x && !x.has("password"))
                        return crow::response(400);

                    user.updateUserPassword(ctx.name,x["password"].s());
                    return crow::response(200);
                });
    }

    void selfRoutes(DB::UserCRUDBase &user, DB::UserRolesBase &userRoles) {

        CROW_ROUTE(app, "/self/delete").methods("DELETE"_method).CROW_MIDDLEWARES(app, AuthorizationMW)
                ([&](const crow::request &req) {
                    auto ctx = app.get_context<AuthorizationMW>(req);
                    user.deleteUser(ctx.name);
                    return crow::response(200);
                });

    }

    void rolesRoutes(DB::RoleCRUDBase &role, DB::UserRolesBase &userRoles) {




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
