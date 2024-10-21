#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include "utils.h"

std::unordered_set<std::string> get_interfaces_names()
{
    std::unordered_set<std::string> names;
    struct ifaddrs *ifap;

    if (getifaddrs(&ifap))
    {
        std::perror("getifaddrs");
        throw std::runtime_error("Failed to get interfaces names");
    }

    struct ifaddrs *cur = ifap;

    while (cur != nullptr)
    {
        std::string name(cur->ifa_name);
        // Currently I only want to support interface with 'en' in their name.
        // TODO: Perhaps add all the interfaces and filter them somehow?
        if (name.rfind("en", 0) == 0)
        {
            names.insert(name);
        }
        cur = cur->ifa_next;
    }

    freeifaddrs(ifap);

    return names;
}