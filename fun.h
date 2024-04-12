//
// Created by bogusz on 12.04.24.
//

#ifndef FUN_H
#define FUN_H
#include <vector>
namespace fun{
    template<typename T>
    std::vector<T> flat(const std::vector<std::vector<T>>& nestedVector) {
        std::vector<T> flattenedVector;
        for (const auto& innerVector : nestedVector) {
            flattenedVector.insert(flattenedVector.end(), innerVector.begin(), innerVector.end());
        }
        return flattenedVector;
    }
}

#endif //FUN_H
