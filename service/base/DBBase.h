//
// Created by bogusz on 30.03.24.
//

#ifndef GROUP_LIST_API_DBBASE_H
#define GROUP_LIST_API_DBBASE_H

namespace DB {

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

    class UserCRUDBase {
    public:
        virtual void createUser(const std::string &name, const std::string &password, const std::string &salt) = 0;
        virtual std::tuple<int, std::string> readUser(const std::string &name) = 0;
        virtual std::vector<std::tuple<int, std::string>> readAllUsers(UserSortBy sortBy = UserSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1, int pageNumber = 1) = 0;
        virtual void updateUserPassword(const std::string &name, const std::string &newPassword) = 0;
        virtual void deleteUser(const std::string &name) = 0;

        virtual ~UserCRUDBase() = default;
    };

    class RoleCRUDBase {
    public:
        virtual void createRole(const std::string &name, long permission, bool isBase) = 0;
        virtual std::tuple<int, std::string, long, bool> readRole(const std::string &name) = 0;
        virtual std::vector<std::tuple<int, std::string, long, bool>> readAllRoles(RoleSortBy sortBy = RoleSortBy::None, SortOrder order = SortOrder::Ascending, int pageSize = -1, int pageNumber = 1, bool isBase = false) = 0;
        virtual void updateRolePermission(const std::string &name, long newPermission) = 0;
        virtual void updateRoleIsBase(const std::string &name, bool newIsBase) = 0;
        virtual void deleteRole(const std::string &name) = 0;

        virtual ~RoleCRUDBase() = default;
    };

    class UserRolesBase {
    public:
        virtual void assignUserRole(const std::string &userName, const std::string &roleName) = 0;
        virtual std::vector<std::string> getUserRoles(const std::string &userName) = 0;
        virtual std::vector<std::string> getUsersWithRole(const std::string &roleName) = 0;
        virtual void removeUserRole(const std::string &userName, const std::string &roleName) = 0;

        virtual ~UserRolesBase() = default;
    };

    class GroupCRUDBase {
    public:
        virtual void createGroup(const std::string &groupName) = 0;
        virtual std::tuple<int, std::string> readGroup(const std::string &groupName) = 0;
        virtual std::vector<std::tuple<int, std::string>> readAllGroups() = 0;
        virtual void updateGroupName(const std::string &oldName, const std::string &newName) = 0;
        virtual void deleteGroup(const std::string &groupName) = 0;

        virtual ~GroupCRUDBase() = default;
    };

//    class GroupUserBase {
//    public:
//        virtual void addUserToGroup(const std::string &userName, const std::string &groupName) = 0;
//        virtual void removeUserFromGroup(const std::string &userName, const std::string &groupName) = 0;
//        virtual std::vector<std::string> getUsersInGroup(const std::string &groupName) = 0;
//        virtual std::vector<std::string> getGroupsForUser(const std::string &userName) = 0;
//
//        virtual ~GroupUserBase() = default;
//    };

    class GroupUserBase {
    public:
        virtual void addUserToGroup(const std::string &userName, const std::string &groupName, long permission) = 0;
        virtual void removeUserFromGroup(const std::string &userName, const std::string &groupName) = 0;
        virtual std::vector<std::tuple<std::string, long>> getUsersInGroup(const std::string &groupName) = 0;
        virtual std::vector<std::string> getGroupsForUser(const std::string &userName) = 0;
        virtual bool isUserInGroup(const std::string &userName, const std::string &groupName) = 0;
        virtual long getUserGroupPermission(const std::string &userName, const std::string &groupName) = 0;

        virtual ~GroupUserBase() = default;
    };
}



#endif //GROUP_LIST_API_DBBASE_H
