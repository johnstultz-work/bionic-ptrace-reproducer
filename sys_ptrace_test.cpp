/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/ptrace.h>

#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#include <memory>

#include <gtest/gtest.h>

//#include <android-base/macros.h>
//#include <android-base/unique_fd.h>
#include "unique_fd.h"

#define UNUSED(x)

//#include "utils.h"

class Errno {
 public:
  Errno(int e) : errno_(e) {}
  int errno_;
};

bool operator==(const Errno& lhs, const Errno& rhs) {
  return lhs.errno_ == rhs.errno_;
}
#define ASSERT_ERRNO(expected_errno) ASSERT_EQ(Errno(expected_errno), Errno(errno))
#define EXPECT_ERRNO(expected_errno) EXPECT_EQ(Errno(expected_errno), Errno(errno))

using namespace std::chrono_literals;

using android::base::unique_fd;

class ChildGuard {
 public:
  explicit ChildGuard(pid_t pid) : pid(pid) {}

  ~ChildGuard() {
    kill(pid, SIGKILL);
    int status;
    TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
  }

 private:
  pid_t pid;
};

enum class HwFeature { Watchpoint, Breakpoint };

static void check_hw_feature_supported(pid_t child, HwFeature feature) {
#if defined(__arm__)
  errno = 0;
  long capabilities;
  long result = ptrace(PTRACE_GETHBPREGS, child, 0, &capabilities);
  if (result == -1) {
    EXPECT_ERRNO(EIO);
    GTEST_SKIP() << "Hardware debug support disabled at kernel configuration time";
  }
  uint8_t hb_count = capabilities & 0xff;
  capabilities >>= 8;
  uint8_t wp_count = capabilities & 0xff;
  capabilities >>= 8;
  uint8_t max_wp_size = capabilities & 0xff;
  if (max_wp_size == 0) {
    GTEST_SKIP() << "Kernel reports zero maximum watchpoint size";
  } else if (feature == HwFeature::Watchpoint && wp_count == 0) {
    GTEST_SKIP() << "Kernel reports zero hardware watchpoints";
  } else if (feature == HwFeature::Breakpoint && hb_count == 0) {
    GTEST_SKIP() << "Kernel reports zero hardware breakpoints";
  }
#elif defined(__aarch64__)
  user_hwdebug_state dreg_state;
  iovec iov;
  iov.iov_base = &dreg_state;
  iov.iov_len = sizeof(dreg_state);

  errno = 0;
  long result = ptrace(PTRACE_GETREGSET, child,
                       feature == HwFeature::Watchpoint ? NT_ARM_HW_WATCH : NT_ARM_HW_BREAK, &iov);
  if (result == -1) {
    ASSERT_ERRNO(EINVAL);
    GTEST_SKIP() << "Hardware support missing";
  } else if ((dreg_state.dbg_info & 0xff) == 0) {
    if (feature == HwFeature::Watchpoint) {
      GTEST_SKIP() << "Kernel reports zero hardware watchpoints";
    } else {
      GTEST_SKIP() << "Kernel reports zero hardware breakpoints";
    }
  }
#else
  // We assume watchpoints and breakpoints are always supported on x86.
  UNUSED(child);
  UNUSED(feature);
#endif
}

static void set_watchpoint(pid_t child, uintptr_t address, size_t size) {
  ASSERT_EQ(0u, address & 0x7) << "address: " << address;
#if defined(__arm__) || defined(__aarch64__)
  const unsigned byte_mask = (1 << size) - 1;
  const unsigned type = 2; // Write.
  const unsigned enable = 1;
  const unsigned control = byte_mask << 5 | type << 3 | enable;

#ifdef __arm__
  ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, -1, &address)) << strerror(errno);
  ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, -2, &control)) << strerror(errno);
#else // aarch64
  user_hwdebug_state dreg_state = {};
  dreg_state.dbg_regs[0].addr = address;
  dreg_state.dbg_regs[0].ctrl = control;

  iovec iov;
  iov.iov_base = &dreg_state;
  iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(dreg_state.dbg_regs[0]);

  ASSERT_EQ(0, ptrace(PTRACE_SETREGSET, child, NT_ARM_HW_WATCH, &iov)) << strerror(errno);
#endif
#elif defined(__i386__) || defined(__x86_64__)
  ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, child, offsetof(user, u_debugreg[0]), address)) << strerror(errno);
  errno = 0;
  unsigned data = ptrace(PTRACE_PEEKUSER, child, offsetof(user, u_debugreg[7]), nullptr);
  ASSERT_ERRNO(0);

  const unsigned size_flag = (size == 8) ? 2 : size - 1;
  const unsigned enable = 1;
  const unsigned type = 1; // Write.

  const unsigned mask = 3 << 18 | 3 << 16 | 1;
  const unsigned value = size_flag << 18 | type << 16 | enable;
  data &= mask;
  data |= value;
  ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, child, offsetof(user, u_debugreg[7]), data)) << strerror(errno);
#else
  UNUSED(child);
  UNUSED(address);
  UNUSED(size);
#endif
}

template <typename T>
static void run_watchpoint_test(std::function<void(T&)> child_func, size_t offset, size_t size) {
  alignas(16) T data{};

  pid_t child = fork();
  ASSERT_NE(-1, child) << strerror(errno);
  if (child == 0) {
    // Extra precaution: make sure we go away if anything happens to our parent.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
      perror("prctl(PR_SET_PDEATHSIG)");
      _exit(1);
    }

    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
      perror("ptrace(PTRACE_TRACEME)");
      _exit(2);
    }

    child_func(data);
    _exit(0);
  }

  ChildGuard guard(child);

  int status;
  ASSERT_EQ(child, TEMP_FAILURE_RETRY(waitpid(child, &status, __WALL))) << strerror(errno);
  ASSERT_TRUE(WIFSTOPPED(status)) << "Status was: " << status;
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status)) << "Status was: " << status;

  check_hw_feature_supported(child, HwFeature::Watchpoint);
  if (::testing::Test::IsSkipped()) {
    return;
  }

  set_watchpoint(child, uintptr_t((&data)) + offset, size);

  ASSERT_EQ(0, ptrace(PTRACE_CONT, child, nullptr, nullptr)) << strerror(errno);
  ASSERT_EQ(child, TEMP_FAILURE_RETRY(waitpid(child, &status, __WALL))) << strerror(errno);
  ASSERT_TRUE(WIFSTOPPED(status)) << "Status was: " << status;
  ASSERT_EQ(SIGTRAP, WSTOPSIG(status)) << "Status was: " << status;

  siginfo_t siginfo;
  ASSERT_EQ(0, ptrace(PTRACE_GETSIGINFO, child, nullptr, &siginfo)) << strerror(errno);
  ASSERT_EQ(TRAP_HWBKPT, siginfo.si_code);
#if defined(__arm__) || defined(__aarch64__)
  ASSERT_LE(&data, siginfo.si_addr);
  ASSERT_GT((&data) + 1, siginfo.si_addr);
#endif
}

template <typename T>
static void watchpoint_stress_child(unsigned cpu, T& data) {
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(cpu, &cpus);
  if (sched_setaffinity(0, sizeof cpus, &cpus) == -1) {
    perror("sched_setaffinity");
    _exit(3);
  }
  raise(SIGSTOP);  // Synchronize with the tracer, let it set the watchpoint.

  data = 1;  // Now trigger the watchpoint.
}

template <typename T>
static void run_watchpoint_stress(size_t cpu) {
  run_watchpoint_test<T>(std::bind(watchpoint_stress_child<T>, cpu, std::placeholders::_1), 0,
                         sizeof(T));
}

// Test watchpoint API. The test is considered successful if our watchpoints get hit OR the
// system reports that watchpoint support is not present. We run the test for different
// watchpoint sizes, while pinning the process to each cpu in turn, for better coverage.
TEST(sys_ptrace, watchpoint_stress) {
  cpu_set_t available_cpus;
  ASSERT_EQ(0, sched_getaffinity(0, sizeof available_cpus, &available_cpus));

  for (size_t cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (!CPU_ISSET(cpu, &available_cpus)) continue;

    run_watchpoint_stress<uint8_t>(cpu);
    if (::testing::Test::IsSkipped()) {
      // Only check first case, since all others would skip for same reason.
      return;
    }
    run_watchpoint_stress<uint16_t>(cpu);
    run_watchpoint_stress<uint32_t>(cpu);
#if defined(__LP64__)
    run_watchpoint_stress<uint64_t>(cpu);
#endif
  }
}


int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
