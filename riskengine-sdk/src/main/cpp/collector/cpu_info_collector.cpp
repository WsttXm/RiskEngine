#include "cpu_info_collector.h"
#include "../util/obf_str.h"
#include "../util/syscall_wrapper.h"

#include <string>
#include <string_view>
#include <vector>

namespace {

std::string_view trim_ws(std::string_view sv) {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
        sv.remove_suffix(1);
    }
    return sv;
}

void push_unique(std::vector<std::string> &out, std::string_view line) {
    if (line.empty()) return;
    for (const auto &existing : out) {
        if (existing == line) return;
    }
    out.emplace_back(line);
}

}  // namespace

std::string get_cpu_info() {
    std::string content = read_file_string(OBF("/proc/cpuinfo").c_str(), 128 * 1024);
    if (content.empty()) return "";

    const auto kHardware = OBF("Hardware");
    const auto kProcessor = OBF("Processor");
    const auto kImpl = OBF("CPU implementer");
    const auto kPart = OBF("CPU part");
    const auto kModelName = OBF("model name");
    const auto kFlags = OBF("flags");
    const auto kHypervisor = OBF("hypervisor");
    const auto kVmx = OBF("vmx");
    const auto kSvm = OBF("svm");

    std::vector<std::string> kept_lines;
    kept_lines.reserve(12);
    bool has_hypervisor = false;
    bool has_vmx = false;
    bool has_svm = false;

    const std::string_view text(content);
    size_t start = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string_view::npos) nl = text.size();
        std::string_view line = text.substr(start, nl - start);
        start = nl + 1;
        while (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }

        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;

        const std::string_view key = trim_ws(line.substr(0, colon));
        const std::string_view val = trim_ws(line.substr(colon + 1));

        if (key == kHardware.view()
                || key == kProcessor.view()
                || key == kImpl.view()
                || key == kPart.view()
                || key == kModelName.view()) {
            push_unique(kept_lines, line);
        } else if (key == kFlags.view()) {
            size_t pos = 0;
            while (pos < val.size()) {
                while (pos < val.size() && (val[pos] == ' ' || val[pos] == '\t')) ++pos;
                if (pos >= val.size()) break;
                size_t end = pos;
                while (end < val.size() && val[end] != ' ' && val[end] != '\t') ++end;
                const std::string_view tok = val.substr(pos, end - pos);
                if (tok == kHypervisor.view()) {
                    has_hypervisor = true;
                } else if (tok == kVmx.view()) {
                    has_vmx = true;
                } else if (tok == kSvm.view()) {
                    has_svm = true;
                }
                pos = end;
            }
        }
    }

    if (has_hypervisor || has_vmx || has_svm) {
        std::string flag_summary;
        flag_summary.reserve(40);
        flag_summary.append(kFlags.data(), kFlags.size());
        flag_summary.append(" : ");
        bool first = true;
        auto append_flag = [&](const auto &flag_tok) {
            if (!first) flag_summary.push_back(' ');
            flag_summary.append(flag_tok.data(), flag_tok.size());
            first = false;
        };
        if (has_hypervisor) append_flag(kHypervisor);
        if (has_vmx) append_flag(kVmx);
        if (has_svm) append_flag(kSvm);
        push_unique(kept_lines, flag_summary);
    }

    std::string result;
    for (size_t i = 0; i < kept_lines.size(); ++i) {
        if (i > 0) result.push_back('|');
        result.append(kept_lines[i]);
    }
    return result;
}
