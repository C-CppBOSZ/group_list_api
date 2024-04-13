#include <utility>

//
// Created by bogusz on 30.03.24.
//

#ifndef GROUP_LIST_API_DBBASE_H
#define GROUP_LIST_API_DBBASE_H

namespace DB {

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

    template<typename T>
    concept PairOrVectorPair = std::is_same_v<T, std::pair<std::string, std::string>> ||
                           std::is_same_v<T, std::vector<std::pair<std::string, std::string>>>;

    template<PairOrVectorPair Arg>
    static void addArgToQuery(const std::string &nameBase, const std::string &definitionBase,Arg arg,const size_t &size,std::vector<std::pair<std::string, std::string>> &query,const int & i) {

        std::pair<std::string, std::string> sql = {nameBase, definitionBase};


        for (int j = 0; j < size; ++j) {
            if constexpr(std::is_same_v<Arg, std::pair<std::string, std::string>>) {
                if ((i & static_cast<int>(std::pow(2, j))) != 0) {
                    sql.first.append(arg.first);
                    sql.second.append(arg.second);
                }
            } else if constexpr(std::is_same_v<Arg, std::vector<std::pair<std::string, std::string>>>) {
                if ((i & static_cast<int>(std::pow(2, j))) != 0) {
                    for (const auto &pair : arg) {
                        query.push_back(pair);
                    }
                }
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

    template<PairOrVectorPair... Args>
    static std::vector<std::pair<std::string, std::string>> prepareDynamicSQLStatementsComplex(
            const std::string &nameBase, const std::string &definitionBase, Args... args) {
        std::vector<std::pair<std::string, std::string>> query = {};
        int i = 0;
        (..., addArgToQuery(nameBase,definitionBase,args,sizeof...(Args),query,i++));

        return query;
    }


    const std::pair<std::string, std::string> sortSQL = {"Sorted", "ORDER BY $# "};
    // std::pair<std::string, std::string> sortSQL = {"Sorted", "ORDER BY $# $# "}; // TODO drugi argument daje error trzeba sprawdzić  czy można wywołać DEC bez drugiego argumentu albo jak dać drugi argument
    const std::pair<std::string, std::string> paginatSQL = {"Paginated", "LIMIT $# OFFSET $# "};
    const std::pair<std::string, std::string> searchSQL = {"Searched", "WHERE $# ILIKE $# "};
    const std::vector<std::vector<std::pair<std::string, std::string> > > defSQL = {
        {
            {"readUser", "SELECT * FROM users WHERE name = $1"},
            {"createUser", "INSERT INTO users (name, password, salt) VALUES ($1, $2, $3)"},
        },
        // prepareDynamicSQLStatements("readAllUsers", "SELECT user_id, name FROM users ", {searchSQL,sortSQL, paginatSQL}),
        prepareDynamicSQLStatementsComplex("readAllUsers","SELECT user_id, name FROM users ",paginatSQL,std::vector{searchSQL}),
    };


    template<typename R>
    struct resDB{
        resDB(bool ok, std::string msg, R *get) : ok(ok), msg(std::move(msg)), get(get) {}

        virtual ~resDB() {
            delete get;
        }

        bool ok;
        std::string msg;
        R* get;
    };

    template<typename R>
    resDB<R> make_res(R*r,const std::string& msg = "successfully."){
        return {true,msg, r};
    }

    template<typename R>
    resDB<R> make_error(R*r,const std::string& msg = "error."){
        return {false,msg, r};
    }

    enum class SortOrder {
        Ascending,
        Descending
    };

    enum class UserSortBy {
        None,
        ID,
        Name
    };

    enum class RoleSortBy {
        None,
        ID,
        Name
    };

    namespace RolePermission {
        long None =      0x0;
        long RoleCU =    0x1;
        long RoleR =     0x10;
        long RoleD =     0x100;
        long UserR =     0x1000;
        long UserU =     0x10000;
        long UserD =     0x100000;
        long assignUserRole = 0x1000000;
        long GroupR =    0x10000000;
        long GroupCU =   0x100000000;
        long GroupD =    0x1000000000;
        long addUserToGroup = 0x10000000000;
        long removeUserFromGroup = 0x100000000000;
        long GroupUserR = 0x1000000000000;
        long All =                 0x1111111111111;
    };

    namespace GroupPermission {
        long None =      0x0;
        long addUserToGroup = 0x1;
        long removeUserFromGroup = 0x10;
        long R = 0x100;
        long D = 0x1000;
        long All = 0x1111;
    };

    class UserCRUDBase {
    public:
        virtual resDB<void> createUser(const std::string &name, const std::string &password, const std::string &salt) = 0;
        virtual resDB<std::tuple<int, std::string, std::string, std::string>> readUser(const std::string &name) = 0;
        virtual resDB<std::vector<std::tuple<int, std::string>>> readAllUsers(UserSortBy sortBy = UserSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1, int pageNumber = 1) = 0;
        virtual resDB<void> updateUserPassword(const std::string &name, const std::string &newPassword) = 0;
        virtual resDB<void> deleteUser(const std::string &name) = 0;
        virtual resDB<int> countUsers() = 0;
//        virtual resDB<bool> verifyPassword(const std::string& name, const std::string& password) = 0;

        virtual ~UserCRUDBase() = default;
    };

    class RoleCRUDBase {
    public:
        virtual resDB<void> createRole(const std::string &name, long permission, bool isBase = false) = 0;
        virtual resDB<std::tuple<int, std::string, long, bool>> readRole(const std::string &name) = 0;
        virtual resDB<std::vector<std::tuple<int, std::string, long, bool>>> readAllRoles(RoleSortBy sortBy = RoleSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1, int pageNumber = 1, bool isBase = false) = 0;
        virtual resDB<void> updateRolePermission(const std::string &name, long newPermission) = 0;
        virtual resDB<void> updateRoleIsBase(const std::string &name, bool newIsBase) = 0;
        virtual resDB<void> deleteRole(const std::string &name) = 0;

        virtual ~RoleCRUDBase() = default;
    };

    class UserRolesBase {
    public:
        virtual resDB<void> assignUserRole(const std::string &userName, const std::string &roleName) = 0;
        virtual resDB<std::vector<std::string>> getUserRoles(const std::string &userName) = 0;
        virtual resDB<std::vector<std::string>> getUsersWithRole(const std::string &roleName) = 0;
        virtual resDB<void> removeUserRole(const std::string &userName, const std::string &roleName) = 0;
        virtual resDB<long> getUserPermissions(const std::string &userName) = 0;

        virtual ~UserRolesBase() = default;
    };

    class GroupCRUDBase {
    public:
        virtual resDB<void> createGroup(const std::string &groupName) = 0;
        virtual resDB<std::tuple<int, std::string>> readGroup(const std::string &groupName) = 0;
        virtual resDB<std::vector<std::tuple<int, std::string>>> readAllGroups() = 0;
        virtual resDB<void> updateGroupName(const std::string &oldName, const std::string &newName) = 0;
        virtual resDB<void> deleteGroup(const std::string &groupName) = 0;

        virtual ~GroupCRUDBase() = default;
    };

    class GroupUserBase {
    public:
        virtual resDB<void> addUserToGroup(const std::string &userName, const std::string &groupName, long permission) = 0;
        virtual resDB<void> removeUserFromGroup(const std::string &userName, const std::string &groupName) = 0;
        virtual resDB<std::vector<std::tuple<std::string, long>>> getUsersInGroup(const std::string &groupName) = 0;
        virtual resDB<std::vector<std::string>> getGroupsForUser(const std::string &userName) = 0;
        virtual resDB<bool> isUserInGroup(const std::string &userName, const std::string &groupName) = 0;
        virtual resDB<long> getUserGroupPermission(const std::string &userName, const std::string &groupName) = 0;

        virtual ~GroupUserBase() = default;
    };
}



#endif //GROUP_LIST_API_DBBASE_H
