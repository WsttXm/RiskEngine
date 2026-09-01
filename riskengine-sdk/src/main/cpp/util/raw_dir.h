#ifndef RISKENGINE_RAW_DIR_H
#define RISKENGINE_RAW_DIR_H

#include <string>
#include <vector>

struct RawDirResult {
    std::vector<std::string> names;
    int error = 0;
    bool ok() const { return error == 0; }
};

RawDirResult raw_list_dir(const char *path);

#endif
