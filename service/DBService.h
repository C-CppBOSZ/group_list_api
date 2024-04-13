//
// Created by bogusz on 30.03.24.
//

#ifndef DBSERVICE_H
#define DBSERVICE_H
#include <iostream>
#include <ostream>
#include <regex>
#include <string>
#include <pqxx/pqxx>
#include <tuple>

#include "../fun.h"
#include "base/DBBase.h"

namespace DB {
    class DBService : public UserCRUDBase, public RoleCRUDBase, public UserRolesBase, public GroupCRUDBase,
                      public GroupUserBase {
    private:
        pqxx::connection conn;

        void prepareSQLStatements(const std::vector<std::pair<std::string, std::string> > &list) {
            for (const auto &[fst, snd]: list) {
                conn.prepare(fst, snd);
            }
        }

        static std::vector<std::pair<std::string, std::string> > prepareDynamicSQLStatements(
            const std::string &nameBase, const std::string &definitionBase,
            const std::vector<std::pair<std::string, std::string> > &dynamicSQL) {
            std::vector<std::pair<std::string, std::string> > query = {};
            const int size = static_cast<int>(std::pow(2, dynamicSQL.size()));
            query.reserve(size);
            for (int i = 0; i < size; ++i) {
                std::pair<std::string, std::string> sql = {nameBase, definitionBase};
                for (int j = 0; j < dynamicSQL.size(); ++j) {
                    if ((i & static_cast<int>(std::pow(2, j))) != 0) {
                        sql.first.append(dynamicSQL[j].first);
                        sql.second.append(dynamicSQL[j].second);
                    }
                }

                int count = 0;
                size_t pos = 0;

                while ((pos = sql.second.find("#", pos)) != std::string::npos) {
                    count++;
                    sql.second.replace(pos,1,std::to_string(count));
                }

                query.emplace_back(sql);
            }

            return query;
        }

        void createSchema() {
            try {
                pqxx::work txn(conn);
                txn.exec(R"(
                    CREATE TABLE IF NOT EXISTS groups (
                        group_id SERIAL PRIMARY KEY,
                        group_name VARCHAR(100) NOT NULL
                    )
                )");

                txn.exec(R"(
                    CREATE TABLE IF NOT EXISTS users (
                        user_id SERIAL PRIMARY KEY,
                        name VARCHAR(50) NOT NULL UNIQUE,
                        password VARCHAR(255) NOT NULL,
                        salt VARCHAR(50) NOT NULL
                    )
                )");

                txn.exec(R"(
                    CREATE TABLE IF NOT EXISTS user_groups (
                        user_id INT REFERENCES users(user_id),
                        group_id INT REFERENCES groups(group_id),
                        PRIMARY KEY (user_id, group_id),
                        permission BIGINT NOT NULL
                    )
                )");

                txn.exec(R"(
                    CREATE TABLE IF NOT EXISTS roles (
                        role_id SERIAL PRIMARY KEY,
                        role_name VARCHAR(100) NOT NULL,
                        permission BIGINT NOT NULL,
                        is_base BOOLEAN NOT NULL
                    )
                )");

                txn.exec(R"(
                    CREATE TABLE IF NOT EXISTS user_roles (
                        user_id INT REFERENCES users(user_id),
                        role_id INT REFERENCES roles(role_id),
                        PRIMARY KEY (user_id, role_id)
                    )
                )");
                txn.commit();
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

    public:
        explicit DBService(const std::string &connection_string)
            : conn(connection_string) {
            createSchema();


            std::pair<std::string, std::string> sortSQL = {"Sorted", "ORDER BY $# $# "};
            std::pair<std::string, std::string> paginatSQL = {"Paginated", "LIMIT $# OFFSET $# "};
            const std::vector<std::vector<std::pair<std::string, std::string> > > defSQL = {
                {
                    {"readUser", "SELECT * FROM users WHERE name = $1"},
                    {"createUser", "INSERT INTO users (name, password, salt) VALUES ($1, $2, $3)"},
                },
                prepareDynamicSQLStatements("readAllUsers", "SELECT user_id, name FROM users ", {sortSQL, paginatSQL}),
            };

            prepareSQLStatements(
                fun::flat(defSQL)
            );

            // createPrepare({"readUser","SELECT * FROM users WHERE name = $1"},{"readUser","SELECT * FROM users WHERE name = $1"});


            // conn.prepare("readUser","SELECT * FROM users WHERE name = $1");
            // DROP DATABASE group ;;//\$
            //            pqxx::work txn(conn);
            //
            //            pqxx::result result = txn.exec_prepared("readUser","DROP DATABASE group ;;//\$");
            //            txn.commit();
            //
            //            std::cout << "jo";
        }

        ~DBService() override = default;

        // USERS

        // Create user
        resDB<void> createUser(const std::string &name, const std::string &password, const std::string &salt) override {
            try {
                pqxx::work txn(conn);
                // txn.exec_params(
                //     "INSERT INTO users (name, password, salt) VALUES ($1, $2, $3)",
                //     name,
                //     password,
                //     salt
                // );
                txn.exec_prepared("createUser", name, password, salt);
                txn.commit();
                std::cout << "User created successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }

        // Read user
        resDB<std::tuple<int, std::string, std::string, std::string> > readUser(const std::string &name) override {
            try {
                pqxx::work txn(conn);

                pqxx::result result = txn.exec_prepared("readUser", name);
                txn.commit();
                if (!result.empty()) {
                    auto *tuple = new std::tuple(result[0]["user_id"].as<int>(),
                                                 result[0]["name"].as<std::string>(),
                                                 result[0]["password"].as<std::string>(),
                                                 result[0]["salt"].as<std::string>());


                    return make_res(tuple);
                } else {
                    return make_error<std::tuple<int, std::string, std::string, std::string> >(nullptr);
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::tuple<int, std::string, std::string, std::string> >(nullptr);
            }
        }

        resDB<std::vector<std::tuple<int, std::string> > > readAllUsers(UserSortBy sortBy = UserSortBy::None,
                                                                        SortOrder order = SortOrder::Ascending,
                                                                        int pageSize = -1,
                                                                        int pageNumber = 1) override {
            auto *users = new std::vector<std::tuple<int, std::string> >();

            try {
                pqxx::work txn(conn);
                std::string sortClause;
                if (sortBy != UserSortBy::None) {
                    std::string sortByField;
                    switch (sortBy) {
                        case UserSortBy::ID:
                            sortByField = "user_id";
                            break;
                        case UserSortBy::Name:
                            sortByField = "name";
                            break;
                    }
                    sortClause = "ORDER BY " + sortByField;
                }

                if (order == SortOrder::Descending) {
                    sortClause += " DESC";
                }

                std::string limitClause;
                if (pageSize > 0) {
                    if (pageNumber < 1) {
                        pageNumber = 1;
                    }
                    int offset = (pageNumber - 1) * pageSize;
                    limitClause = "LIMIT " + std::to_string(pageSize) + " OFFSET " + std::to_string(offset);
                }

                std::string query = "SELECT user_id, name FROM users " + sortClause + " " + limitClause;
                pqxx::result result = txn.exec(query);
                txn.commit();

                for (const auto &row: result) {
                    users->emplace_back(row["user_id"].as<int>(), row["name"].as<std::string>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::tuple<int, std::string> > >(nullptr, e.what());
            }

            if (users->empty()) {
                return make_error<std::vector<std::tuple<int, std::string> > >(nullptr, "empty.");
            }
            return make_res(users);
        }

        // Update user password
        resDB<void> updateUserPassword(const std::string &name, const std::string &newPassword) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "UPDATE users SET password = $1 WHERE name = $2",
                    newPassword,
                    name
                );
                txn.commit();
                std::cout << "User password updated successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }

        // Delete user
        resDB<void> deleteUser(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "DELETE FROM users WHERE name = $1",
                    name
                );
                txn.commit();
                std::cout << "User deleted successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // Count users
        resDB<int> countUsers() override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec("SELECT COUNT(*) FROM users");
                txn.commit();

                if (!result.empty()) {
                    int count = result[0][0].as<int>();
                    return make_res(new int(count));
                } else {
                    return make_res(new int(0));
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<int>(nullptr, e.what());
            }
        }

        //        bool verifyPassword(const std::string& name, const std::string& password) {
        //            try {
        //                pqxx::nontransaction txn(conn);
        //                std::string query = "SELECT password, salt FROM users WHERE name = $1";
        //                pqxx::result res = txn.exec_params(query, name);
        //                if (res.size() == 1) {
        //                    std::string stored_password = res[0][0].as<std::string>();
        //                    std::string salt = res[0][1].as<std::string>();
        //                    std::string hashed_password = routes::generateHashedPassword(password, salt);
        //                    return stored_password == hashed_password;
        //                }
        //                return false;
        //            } catch (const std::exception& e) {
        //                std::cerr << "Database error: " << e.what() << std::endl;
        //                return false;
        //            }
        //        }

        // role

        // Create role
        resDB<void> createRole(const std::string &name, long permission, bool isBase = false) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "INSERT INTO roles (role_name, permission, is_base) VALUES ($1, $2, $3)",
                    name,
                    permission,
                    isBase
                );
                txn.commit();
                std::cout << "Role created successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // Read role
        resDB<std::tuple<int, std::string, long, bool> > readRole(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec_params(
                    "SELECT role_id, role_name, permission, is_base FROM roles WHERE role_name = $1",
                    name
                );
                txn.commit();
                if (!result.empty()) {
                    auto row = result[0];
                    auto *role = new std::tuple<int, std::string, long, bool>(
                        row["role_id"].as<int>(),
                        row["role_name"].as<std::string>(),
                        row["permission"].as<long>(),
                        row["is_base"].as<bool>()
                    );
                    return make_res(role);
                } else {
                    return make_error<std::tuple<int, std::string, long, bool> >(nullptr);
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::tuple<int, std::string, long, bool> >(nullptr, e.what());
            }
        }


        // Read all roles
        resDB<std::vector<std::tuple<int, std::string, long, bool> > > readAllRoles(
            RoleSortBy sortBy = RoleSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1,
            int pageNumber = 1, bool isBase = false) override {
            auto roles = new std::vector<std::tuple<int, std::string, long, bool> >();

            try {
                pqxx::work txn(conn);
                std::string sortClause;
                if (sortBy != RoleSortBy::None) {
                    std::string sortByField;
                    switch (sortBy) {
                        case RoleSortBy::ID:
                            sortByField = "role_id";
                            break;
                        case RoleSortBy::Name:
                            sortByField = "role_name";
                            break;
                    }
                    sortClause = "ORDER BY " + sortByField;
                    if (order == SortOrder::Descending) {
                        sortClause += " DESC";
                    }
                }

                std::string baseClause;
                if (isBase) {
                    baseClause = "WHERE is_base = true";
                }

                std::string limitClause;
                if (pageSize > 0) {
                    if (pageNumber < 1) {
                        pageNumber = 1;
                    }
                    int offset = (pageNumber - 1) * pageSize;
                    limitClause = "LIMIT " + std::to_string(pageSize) + " OFFSET " + std::to_string(offset);
                }

                std::string query = "SELECT role_id, role_name, permission, is_base FROM roles " + baseClause + " " +
                                    sortClause + " " + limitClause;
                pqxx::result result = txn.exec(query);
                txn.commit();

                for (const auto &row: result) {
                    roles->emplace_back(row["role_id"].as<int>(), row["role_name"].as<std::string>(),
                                        row["permission"].as<long>(), row["is_base"].as<bool>());
                }
                return make_res(roles);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::tuple<int, std::string, long, bool> > >(nullptr, e.what());
            }
        }


        // Update role permission
        resDB<void> updateRolePermission(const std::string &name, long newPermission) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "UPDATE roles SET permission = $1 WHERE role_name = $2",
                    newPermission,
                    name
                );
                txn.commit();
                std::cout << "Role permission updated successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }

        // Update role is_base
        resDB<void> updateRoleIsBase(const std::string &name, bool newIsBase) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "UPDATE roles SET is_base = $1 WHERE role_name = $2",
                    newIsBase,
                    name
                );
                txn.commit();
                std::cout << "Role is_base updated successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }

        // Delete role
        resDB<void> deleteRole(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "DELETE FROM roles WHERE role_name = $1",
                    name
                );
                txn.commit();
                std::cout << "Role deleted successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // UserRolesBase

        // Assign user role
        resDB<void> assignUserRole(const std::string &userName, const std::string &roleName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User not found." << std::endl;
                    return make_error<void>(nullptr, "User not found.");
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result roleResult = txn.exec_params(
                    "SELECT role_id FROM roles WHERE role_name = $1",
                    roleName
                );
                if (roleResult.empty()) {
                    std::cerr << "Role not found." << std::endl;
                    return make_error<void>(nullptr, "Role not found.");
                }
                int roleId = roleResult[0]["role_id"].as<int>();

                txn.exec_params(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
                    userId,
                    roleId
                );
                txn.commit();
                std::cout << "User role assigned successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // Get user roles
        resDB<std::vector<std::string> > getUserRoles(const std::string &userName) override {
            auto roles = new std::vector<std::string>();

            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User not found." << std::endl;
                    return make_res<std::vector<std::string> >(roles);
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result result = txn.exec_params(
                    "SELECT r.role_name FROM roles r JOIN user_roles ur ON r.role_id = ur.role_id WHERE ur.user_id = $1",
                    userId
                );
                txn.commit();

                for (const auto &row: result) {
                    roles->push_back(row["role_name"].as<std::string>());
                }
                return make_res(roles);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::string> >(nullptr, e.what());
            }
        }


        // Get users with role
        resDB<std::vector<std::string> > getUsersWithRole(const std::string &roleName) override {
            auto users = new std::vector<std::string>();

            try {
                pqxx::work txn(conn);

                pqxx::result roleResult = txn.exec_params(
                    "SELECT role_id FROM roles WHERE role_name = $1",
                    roleName
                );
                if (roleResult.empty()) {
                    std::cerr << "Role not found." << std::endl;
                    return make_res<std::vector<std::string> >(users);
                }
                int roleId = roleResult[0]["role_id"].as<int>();

                pqxx::result result = txn.exec_params(
                    "SELECT u.name FROM users u JOIN user_roles ur ON u.user_id = ur.user_id WHERE ur.role_id = $1",
                    roleId
                );
                txn.commit();

                for (const auto &row: result) {
                    users->push_back(row["name"].as<std::string>());
                }
                return make_res(users);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::string> >(nullptr, e.what());
            }
        }


        // Remove user role
        resDB<void> removeUserRole(const std::string &userName, const std::string &roleName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User not found." << std::endl;
                    return make_error<void>(nullptr, "User not found.");
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result roleResult = txn.exec_params(
                    "SELECT role_id FROM roles WHERE role_name = $1",
                    roleName
                );
                if (roleResult.empty()) {
                    std::cerr << "Role not found." << std::endl;
                    return make_error<void>(nullptr, "Role not found.");
                }
                int roleId = roleResult[0]["role_id"].as<int>();

                txn.exec_params(
                    "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
                    userId,
                    roleId
                );
                txn.commit();
                std::cout << "User role removed successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }

        // Get user permissions
        resDB<long> getUserPermissions(const std::string &userName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return make_error<long>(nullptr, "User '" + userName + "' does not exist.");
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result roleResult = txn.exec_params(
                    "SELECT roles.permission "
                    "FROM roles "
                    "JOIN user_roles ON roles.role_id = user_roles.role_id "
                    "WHERE user_roles.user_id = $1",
                    userId
                );

                txn.commit();

                long userPermissions = 0;
                for (const auto &row: roleResult) {
                    userPermissions |= row["permission"].as<long>();
                }
                return make_res(new long(userPermissions));
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<long>(nullptr, e.what());
            }
        }

        // group

        // Create group
        resDB<void> createGroup(const std::string &groupName) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "INSERT INTO groups (group_name) VALUES ($1)",
                    groupName
                );
                txn.commit();
                std::cout << "Group created successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // Read group
        resDB<std::tuple<int, std::string> > readGroup(const std::string &groupName) override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec_params(
                    "SELECT group_id, group_name FROM groups WHERE group_name = $1",
                    groupName
                );
                txn.commit();
                if (!result.empty()) {
                    int groupId = result[0]["group_id"].as<int>();
                    std::string name = result[0]["group_name"].as<std::string>();
                    return make_res(new std::tuple(std::make_tuple(groupId, name)));
                } else {
                    return make_error<std::tuple<int, std::string> >(nullptr, "empty.");
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::tuple<int, std::string> >(nullptr, e.what());
            }
        }

        // Read all groups
        resDB<std::vector<std::tuple<int, std::string> > > readAllGroups() override {
            auto groups = new std::vector<std::tuple<int, std::string> >();

            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec("SELECT group_id, group_name FROM groups");
                txn.commit();

                for (const auto &row: result) {
                    groups->emplace_back(row["group_id"].as<int>(), row["group_name"].as<std::string>());
                }
                return make_res(groups);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::tuple<int, std::string> > >(nullptr, e.what());
            }
        }

        // Update group name
        resDB<void> updateGroupName(const std::string &oldName, const std::string &newName) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "UPDATE groups SET group_name = $1 WHERE group_name = $2",
                    newName,
                    oldName
                );
                txn.commit();
                std::cout << "Group name updated successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }

        // Delete group
        resDB<void> deleteGroup(const std::string &groupName) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                    "DELETE FROM groups WHERE group_name = $1",
                    groupName
                );
                txn.commit();
                std::cout << "Group deleted successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // GroupUserBase

        // Add user to group
        resDB<void> addUserToGroup(const std::string &userName, const std::string &groupName,
                                   long permission) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return make_error<void>(nullptr, "User '" + userName + "' does not exist.");
                }

                pqxx::result groupResult = txn.exec_params(
                    "SELECT group_id FROM groups WHERE group_name = $1",
                    groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return make_error<void>(nullptr, "Group '" + groupName + "' does not exist.");
                }

                txn.exec_params(
                    "INSERT INTO user_groups (user_id, group_id, permission) "
                    "VALUES ($1, $2, $3)",
                    userResult[0]["user_id"].as<int>(),
                    groupResult[0]["group_id"].as<int>(),
                    permission
                );
                txn.commit();
                std::cout << "User added to group successfully." << std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // Remove user from group
        resDB<void> removeUserFromGroup(const std::string &userName, const std::string &groupName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return make_error<void>(nullptr, "User '" + userName + "' does not exist.");
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result groupResult = txn.exec_params(
                    "SELECT group_id FROM groups WHERE group_name = $1",
                    groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return make_error<void>(nullptr, "Group '" + groupName + "' does not exist.");
                }
                int groupId = groupResult[0]["group_id"].as<int>();

                txn.exec_params(
                    "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
                    userId,
                    groupId
                );
                txn.commit();
                std::cout << "User '" << userName << "' removed from group '" << groupName << "' successfully." <<
                        std::endl;
                return make_res<void>(nullptr);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<void>(nullptr, e.what());
            }
        }


        // Get users in group
        resDB<std::vector<std::tuple<std::string, long> > > getUsersInGroup(const std::string &groupName) override {
            auto users = new std::vector<std::tuple<std::string, long> >();

            try {
                pqxx::work txn(conn);

                pqxx::result groupResult = txn.exec_params(
                    "SELECT group_id FROM groups WHERE group_name = $1",
                    groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return make_error<std::vector<std::tuple<std::string, long> > >(
                        nullptr, "Group '" + groupName + "' does not exist.");
                }

                pqxx::result result = txn.exec_params(
                    "SELECT users.name, user_groups.permission "
                    "FROM users "
                    "JOIN user_groups ON users.user_id = user_groups.user_id "
                    "JOIN groups ON user_groups.group_id = groups.group_id "
                    "WHERE groups.group_name = $1",
                    groupName
                );
                txn.commit();

                for (const auto &row: result) {
                    users->emplace_back(row["name"].as<std::string>(), row["permission"].as<long>());
                }
                return make_res(users);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::tuple<std::string, long> > >(nullptr, e.what());
            }
        }


        // Get groups for user
        resDB<std::vector<std::string> > getGroupsForUser(const std::string &userName) override {
            auto groups = new std::vector<std::string>();

            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return make_error<std::vector<std::string> >(nullptr, "User '" + userName + "' does not exist.");
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result result = txn.exec_params(
                    "SELECT g.group_name FROM groups g INNER JOIN user_groups ug ON g.group_id = ug.group_id WHERE ug.user_id = $1",
                    userId
                );
                txn.commit();

                for (const auto &row: result) {
                    groups->push_back(row["group_name"].as<std::string>());
                }
                return make_res(groups);
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<std::vector<std::string> >(nullptr, e.what());
            }
        }


        // Check if user is in group
        resDB<bool> isUserInGroup(const std::string &userName, const std::string &groupName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return make_res(new bool(false));
                }

                pqxx::result groupResult = txn.exec_params(
                    "SELECT group_id FROM groups WHERE group_name = $1",
                    groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return make_res(new bool(false));
                }

                pqxx::result result = txn.exec_params(
                    "SELECT COUNT(*) "
                    "FROM user_groups "
                    "WHERE user_id = $1 AND group_id = $2",
                    userResult[0]["user_id"].as<int>(),
                    groupResult[0]["group_id"].as<int>()
                );
                txn.commit();

                return make_res(new bool(result[0][0].as<int>() > 0));
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<bool>(nullptr, e.what());
            }
        }


        // Get user group permission
        resDB<long> getUserGroupPermission(const std::string &userName, const std::string &groupName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                    "SELECT user_id FROM users WHERE name = $1",
                    userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return make_res(new long(0));
                }

                pqxx::result groupResult = txn.exec_params(
                    "SELECT group_id FROM groups WHERE group_name = $1",
                    groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return make_res(new long(0));
                }

                pqxx::result result = txn.exec_params(
                    "SELECT permission "
                    "FROM user_groups "
                    "WHERE user_id = $1 AND group_id = $2",
                    userResult[0]["user_id"].as<int>(),
                    groupResult[0]["group_id"].as<int>()
                );
                txn.commit();

                if (!result.empty()) {
                    return make_res(new long(result[0]["permission"].as<long>()));
                } else {
                    return make_res(new long(0));
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return make_error<long>(nullptr, e.what());
            }
        }
    };
}

#endif //DBSERVICE_H
