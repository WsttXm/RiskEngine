#ifndef RISKENGINE_MINI_GTEST_H
#define RISKENGINE_MINI_GTEST_H

#if defined(RISKENGINE_USING_SYSTEM_GTEST) && RISKENGINE_USING_SYSTEM_GTEST
#include <gtest/gtest.h>
#define RISKENGINE_DEFINE_TEST_MAIN()
#else

#include <cmath>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace mini_gtest {

struct TestCase {
    std::string suite;
    std::string name;
    void (*fn)();
};

struct TestState {
    int current_failures = 0;
    int total_passed = 0;
    int total_failed = 0;
};

inline std::vector<TestCase> &registry() {
    static std::vector<TestCase> tests;
    return tests;
}

inline TestState &state() {
    static TestState s;
    return s;
}

struct Registrar {
    Registrar(const char *suite, const char *name, void (*fn)()) {
        registry().push_back({suite, name, fn});
    }
};

struct AssertionAbort : public std::exception {
    const char *what() const noexcept override { return "ASSERT_* failed"; }
};

inline void record_failure(const char *file, int line, const std::string &msg) {
    state().current_failures++;
    std::cerr << "  [FAIL] " << file << ":" << line << ": " << msg << "\n";
}

template <typename A, typename B>
inline std::string format_cmp(const char *lhs_expr, const char *op,
                              const char *rhs_expr, const A &lhs, const B &rhs) {
    std::ostringstream oss;
    oss << lhs_expr << " " << op << " " << rhs_expr
        << " (lhs=" << lhs << ", rhs=" << rhs << ")";
    return oss.str();
}

inline bool matches_filter(const std::string &full_name, const std::string &filter) {
    if (filter.empty() || filter == "*") {
        return true;
    }
    if (filter.back() == '*') {
        return full_name.rfind(filter.substr(0, filter.size() - 1), 0) == 0;
    }
    return full_name == filter || full_name.find(filter) != std::string::npos;
}

inline int run_all(int argc, char **argv) {
    std::string filter;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const std::string prefix = "--gtest_filter=";
        if (arg.rfind(prefix, 0) == 0) {
            filter = arg.substr(prefix.size());
        }
    }

    auto &tests = registry();
    auto &st = state();
    st.total_passed = 0;
    st.total_failed = 0;

    std::cout << "[==========] Running " << tests.size() << " test(s) (mini_gtest offline runner)\n";
    for (const auto &tc : tests) {
        const std::string full = tc.suite + "." + tc.name;
        if (!matches_filter(full, filter)) {
            continue;
        }
        st.current_failures = 0;
        std::cout << "[ RUN      ] " << full << "\n";
        try {
            tc.fn();
        } catch (const AssertionAbort &) {
            // Already recorded.
        } catch (const std::exception &e) {
            record_failure(__FILE__, __LINE__, std::string("Uncaught std::exception: ") + e.what());
        } catch (...) {
            record_failure(__FILE__, __LINE__, "Uncaught unknown exception");
        }
        if (st.current_failures == 0) {
            st.total_passed++;
            std::cout << "[       OK ] " << full << "\n";
        } else {
            st.total_failed++;
            std::cout << "[  FAILED  ] " << full << "\n";
        }
    }

    std::cout << "[==========] " << (st.total_passed + st.total_failed)
              << " test(s) ran: " << st.total_passed << " passed, "
              << st.total_failed << " failed.\n";
    return st.total_failed == 0 ? 0 : 1;
}

}  // namespace mini_gtest

#define TEST(SuiteName, TestName) \
    static void RiskEngineTest_##SuiteName##_##TestName(); \
    static ::mini_gtest::Registrar RiskEngineReg_##SuiteName##_##TestName( \
            #SuiteName, #TestName, &RiskEngineTest_##SuiteName##_##TestName); \
    static void RiskEngineTest_##SuiteName##_##TestName()

#define EXPECT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            ::mini_gtest::record_failure(__FILE__, __LINE__, std::string("Expected true: ") + #cond); \
        } \
    } while (0)

#define EXPECT_FALSE(cond) \
    do { \
        if (cond) { \
            ::mini_gtest::record_failure(__FILE__, __LINE__, std::string("Expected false: ") + #cond); \
        } \
    } while (0)

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            ::mini_gtest::record_failure(__FILE__, __LINE__, std::string("Asserted true: ") + #cond); \
            throw ::mini_gtest::AssertionAbort(); \
        } \
    } while (0)

#define ASSERT_FALSE(cond) \
    do { \
        if (cond) { \
            ::mini_gtest::record_failure(__FILE__, __LINE__, std::string("Asserted false: ") + #cond); \
            throw ::mini_gtest::AssertionAbort(); \
        } \
    } while (0)

#define MINI_GTEST_CMP_IMPL(a, b, op, is_assert) \
    do { \
        const auto &_lhs = (a); \
        const auto &_rhs = (b); \
        if (!(_lhs op _rhs)) { \
            ::mini_gtest::record_failure( \
                    __FILE__, __LINE__, ::mini_gtest::format_cmp(#a, #op, #b, _lhs, _rhs)); \
            if (is_assert) { \
                throw ::mini_gtest::AssertionAbort(); \
            } \
        } \
    } while (0)

#define EXPECT_EQ(a, b) MINI_GTEST_CMP_IMPL(a, b, ==, false)
#define EXPECT_NE(a, b) MINI_GTEST_CMP_IMPL(a, b, !=, false)
#define EXPECT_LT(a, b) MINI_GTEST_CMP_IMPL(a, b, <, false)
#define EXPECT_LE(a, b) MINI_GTEST_CMP_IMPL(a, b, <=, false)
#define EXPECT_GT(a, b) MINI_GTEST_CMP_IMPL(a, b, >, false)
#define EXPECT_GE(a, b) MINI_GTEST_CMP_IMPL(a, b, >=, false)

#define ASSERT_EQ(a, b) MINI_GTEST_CMP_IMPL(a, b, ==, true)
#define ASSERT_NE(a, b) MINI_GTEST_CMP_IMPL(a, b, !=, true)
#define ASSERT_LT(a, b) MINI_GTEST_CMP_IMPL(a, b, <, true)
#define ASSERT_LE(a, b) MINI_GTEST_CMP_IMPL(a, b, <=, true)
#define ASSERT_GT(a, b) MINI_GTEST_CMP_IMPL(a, b, >, true)
#define ASSERT_GE(a, b) MINI_GTEST_CMP_IMPL(a, b, >=, true)

#define EXPECT_STREQ(a, b) \
    do { \
        const char *_sa = (a); \
        const char *_sb = (b); \
        if (_sa == nullptr || _sb == nullptr || std::strcmp(_sa, _sb) != 0) { \
            ::mini_gtest::record_failure( \
                    __FILE__, __LINE__, \
                    std::string("Expected C-string equality: ") + (_sa ? _sa : "<null>") \
                            + " vs " + (_sb ? _sb : "<null>")); \
        } \
    } while (0)

#define RISKENGINE_DEFINE_TEST_MAIN() \
    int main(int argc, char **argv) { \
        return ::mini_gtest::run_all(argc, argv); \
    }

#endif  // RISKENGINE_USING_SYSTEM_GTEST
#endif  // RISKENGINE_MINI_GTEST_H
