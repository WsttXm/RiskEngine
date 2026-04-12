#include "system_property_collector.h"
#include <sys/system_properties.h>
#include <string>

std::string get_system_property(const char *name) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(name, value);
    return std::string(value);
}
