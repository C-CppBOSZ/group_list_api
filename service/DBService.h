//
// Created by bogusz on 30.03.24.
//

#ifndef DBSERVICE_H
#define DBSERVICE_H
#include <iostream>
#include <ostream>
#include <string>
#include <pqxx/pqxx>
#include <tuple>

#include "base/DBBase.h"
namespace DB {

    class DBService : public UserCRUDBase, public RoleCRUDBase, public UserRolesBase, public GroupCRUDBase, public GroupUserBase{
    private:
        pqxx::connection conn;

    public:
        explicit DBService(const std::string &connection_string)
                : conn(connection_string) {
            createSchema();
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
                        name VARCHAR(50) NOT NULL,
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

        // USERS

        // Create user
        void createUser(const std::string &name, const std::string &password, const std::string &salt) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "INSERT INTO users (name, password, salt) VALUES ($1, $2, $3)",
                        name,
                        password,
                        salt
                );
                txn.commit();
                std::cout << "User created successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        // Read user
        std::tuple<int, std::string> readUser(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec_params(
                        "SELECT user_id, name FROM users WHERE name = $1",
                        name
                );
                txn.commit();
                if (!result.empty()) {
                    return std::make_tuple(result[0]["user_id"].as<int>(), result[0]["name"].as<std::string>());
                } else {
                    return std::make_tuple(-1, "");
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return std::make_tuple(-1, "");
            }
        }

        std::vector<std::tuple<int, std::string>> readAllUsers(UserSortBy sortBy = UserSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1, int pageNumber = 1) override {
            std::vector<std::tuple<int, std::string>> users;

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

                for (const auto &row : result) {
                    users.emplace_back(row["user_id"].as<int>(), row["name"].as<std::string>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return users;
        }

        // Update user password
        void updateUserPassword(const std::string &name, const std::string &newPassword) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "UPDATE users SET password = $1 WHERE name = $2",
                        newPassword,
                        name
                );
                txn.commit();
                std::cout << "User password updated successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        // Delete user
        void deleteUser(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "DELETE FROM users WHERE name = $1",
                        name
                );
                txn.commit();
                std::cout << "User deleted successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        int countUsers() override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec("SELECT COUNT(*) FROM users");
                txn.commit();

                if (!result.empty()) {
                    return result[0][0].as<int>();
                } else {
                    return 0;
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return 0;
            }
        }

        // role

        void createRole(const std::string &name, long permission, bool isBase = false) override {
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
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        std::tuple<int, std::string, long, bool> readRole(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec_params(
                        "SELECT role_id, role_name, permission, is_base FROM roles WHERE role_name = $1",
                        name
                );
                txn.commit();
                if (!result.empty()) {
                    auto row = result[0];
                    return std::make_tuple(row["role_id"].as<int>(), row["role_name"].as<std::string>(), row["permission"].as<long>(), row["is_base"].as<bool>());
                } else {
                    return std::make_tuple(-1, "", 0, false);
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return std::make_tuple(-1, "", 0, false);
            }
        }

        std::vector<std::tuple<int, std::string, long, bool>> readAllRoles(RoleSortBy sortBy = RoleSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1, int pageNumber = 1, bool isBase = false) override {
            std::vector<std::tuple<int, std::string, long, bool>> roles;

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

                std::string query = "SELECT role_id, role_name, permission, is_base FROM roles " + baseClause + " " + sortClause + " " + limitClause;
                pqxx::result result = txn.exec(query);
                txn.commit();

                for (const auto &row : result) {
                    roles.emplace_back(row["role_id"].as<int>(), row["role_name"].as<std::string>(), row["permission"].as<long>(), row["is_base"].as<bool>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return roles;
        }

        void updateRolePermission(const std::string &name, long newPermission) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "UPDATE roles SET permission = $1 WHERE role_name = $2",
                        newPermission,
                        name
                );
                txn.commit();
                std::cout << "Role permission updated successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        void updateRoleIsBase(const std::string &name, bool newIsBase) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "UPDATE roles SET is_base = $1 WHERE role_name = $2",
                        newIsBase,
                        name
                );
                txn.commit();
                std::cout << "Role is_base updated successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        void deleteRole(const std::string &name) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "DELETE FROM roles WHERE role_name = $1",
                        name
                );
                txn.commit();
                std::cout << "Role deleted successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        // UserRolesBase

        void assignUserRole(const std::string &userName, const std::string &roleName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User not found." << std::endl;
                    return;
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result roleResult = txn.exec_params(
                        "SELECT role_id FROM roles WHERE role_name = $1",
                        roleName
                );
                if (roleResult.empty()) {
                    std::cerr << "Role not found." << std::endl;
                    return;
                }
                int roleId = roleResult[0]["role_id"].as<int>();

                txn.exec_params(
                        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
                        userId,
                        roleId
                );
                txn.commit();
                std::cout << "User role assigned successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        std::vector<std::string> getUserRoles(const std::string &userName) override {
            std::vector<std::string> roles;

            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User not found." << std::endl;
                    return roles;
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result result = txn.exec_params(
                        "SELECT r.role_name FROM roles r JOIN user_roles ur ON r.role_id = ur.role_id WHERE ur.user_id = $1",
                        userId
                );
                txn.commit();

                for (const auto &row : result) {
                    roles.push_back(row["role_name"].as<std::string>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return roles;
        }

        std::vector<std::string> getUsersWithRole(const std::string &roleName) override {
            std::vector<std::string> users;

            try {
                pqxx::work txn(conn);

                pqxx::result roleResult = txn.exec_params(
                        "SELECT role_id FROM roles WHERE role_name = $1",
                        roleName
                );
                if (roleResult.empty()) {
                    std::cerr << "Role not found." << std::endl;
                    return users;
                }
                int roleId = roleResult[0]["role_id"].as<int>();

                pqxx::result result = txn.exec_params(
                        "SELECT u.name FROM users u JOIN user_roles ur ON u.user_id = ur.user_id WHERE ur.role_id = $1",
                        roleId
                );
                txn.commit();

                for (const auto &row : result) {
                    users.push_back(row["name"].as<std::string>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return users;
        }

        void removeUserRole(const std::string &userName, const std::string &roleName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User not found." << std::endl;
                    return;
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result roleResult = txn.exec_params(
                        "SELECT role_id FROM roles WHERE role_name = $1",
                        roleName
                );
                if (roleResult.empty()) {
                    std::cerr << "Role not found." << std::endl;
                    return;
                }
                int roleId = roleResult[0]["role_id"].as<int>();

                txn.exec_params(
                        "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
                        userId,
                        roleId
                );
                txn.commit();
                std::cout << "User role removed successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        long getUserPermissions(const std::string &userName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return 0;
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
                for (const auto &row : roleResult) {
                    userPermissions |= row["permission"].as<long>();
                }
                return userPermissions;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return 0;
            }
        }
        // group

        void createGroup(const std::string &groupName) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "INSERT INTO groups (group_name) VALUES ($1)",
                        groupName
                );
                txn.commit();
                std::cout << "Group created successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        std::tuple<int, std::string> readGroup(const std::string &groupName) override {
            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec_params(
                        "SELECT group_id, group_name FROM groups WHERE group_name = $1",
                        groupName
                );
                txn.commit();
                if (!result.empty()) {
                    return std::make_tuple(result[0]["group_id"].as<int>(), result[0]["group_name"].as<std::string>());
                } else {
                    return std::make_tuple(-1, "");
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return std::make_tuple(-1, "");
            }
        }

        std::vector<std::tuple<int, std::string>> readAllGroups() override {
            std::vector<std::tuple<int, std::string>> groups;

            try {
                pqxx::work txn(conn);
                pqxx::result result = txn.exec("SELECT group_id, group_name FROM groups");
                txn.commit();

                for (const auto &row : result) {
                    groups.emplace_back(row["group_id"].as<int>(), row["group_name"].as<std::string>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return groups;
        }

        void updateGroupName(const std::string &oldName, const std::string &newName) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "UPDATE groups SET group_name = $1 WHERE group_name = $2",
                        newName,
                        oldName
                );
                txn.commit();
                std::cout << "Group name updated successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        void deleteGroup(const std::string &groupName) override {
            try {
                pqxx::work txn(conn);
                txn.exec_params(
                        "DELETE FROM groups WHERE group_name = $1",
                        groupName
                );
                txn.commit();
                std::cout << "Group deleted successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        // GroupUserBase

        void addUserToGroup(const std::string &userName, const std::string &groupName, long permission) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return;
                }

                pqxx::result groupResult = txn.exec_params(
                        "SELECT group_id FROM groups WHERE group_name = $1",
                        groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return;
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
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        void removeUserFromGroup(const std::string &userName, const std::string &groupName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return;
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result groupResult = txn.exec_params(
                        "SELECT group_id FROM groups WHERE group_name = $1",
                        groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return;
                }
                int groupId = groupResult[0]["group_id"].as<int>();

                txn.exec_params(
                        "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
                        userId,
                        groupId
                );
                txn.commit();
                std::cout << "User '" << userName << "' removed from group '" << groupName << "' successfully." << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }
        }

        std::vector<std::tuple<std::string, long>> getUsersInGroup(const std::string &groupName) override {
            std::vector<std::tuple<std::string, long>> users;

            try {
                pqxx::work txn(conn);

                pqxx::result groupResult = txn.exec_params(
                        "SELECT group_id FROM groups WHERE group_name = $1",
                        groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return users;
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

                for (const auto &row : result) {
                    users.emplace_back(row["name"].as<std::string>(), row["permission"].as<long>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return users;
        }

        std::vector<std::string> getGroupsForUser(const std::string &userName) override {
            std::vector<std::string> groups;

            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return groups;
                }
                int userId = userResult[0]["user_id"].as<int>();

                pqxx::result result = txn.exec_params(
                        "SELECT g.group_name FROM groups g INNER JOIN user_groups ug ON g.group_id = ug.group_id WHERE ug.user_id = $1",
                        userId
                );
                txn.commit();

                for (const auto &row : result) {
                    groups.push_back(row["group_name"].as<std::string>());
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
            }

            return groups;
        }

        bool isUserInGroup(const std::string &userName, const std::string &groupName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return false;
                }

                pqxx::result groupResult = txn.exec_params(
                        "SELECT group_id FROM groups WHERE group_name = $1",
                        groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return false;
                }

                pqxx::result result = txn.exec_params(
                        "SELECT COUNT(*) "
                        "FROM user_groups "
                        "WHERE user_id = $1 AND group_id = $2",
                        userResult[0]["user_id"].as<int>(),
                        groupResult[0]["group_id"].as<int>()
                );
                txn.commit();

                return result[0][0].as<int>() > 0;
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return false;
            }
        }

        long getUserGroupPermission(const std::string &userName, const std::string &groupName) override {
            try {
                pqxx::work txn(conn);

                pqxx::result userResult = txn.exec_params(
                        "SELECT user_id FROM users WHERE name = $1",
                        userName
                );
                if (userResult.empty()) {
                    std::cerr << "User '" << userName << "' does not exist." << std::endl;
                    return 0;
                }

                pqxx::result groupResult = txn.exec_params(
                        "SELECT group_id FROM groups WHERE group_name = $1",
                        groupName
                );
                if (groupResult.empty()) {
                    std::cerr << "Group '" << groupName << "' does not exist." << std::endl;
                    return 0;
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
                    return result[0]["permission"].as<long>();
                } else {
                    return 0;
                }
            } catch (const std::exception &e) {
                std::cerr << "Database error: " << e.what() << std::endl;
                return 0;
            }
        }

    };
}

#endif //DBSERVICE_H
