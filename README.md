# bionic ptrace issue reproducer

This is just a reproducer demonstrating a kernel issue found using the
Bionic sys_ptrace_test code found here:
https://android.googlesource.com/platform/bionic/+/main/tests/sys_ptrace_test.cpp

I've tweaked it so it builds under a classic Linux environment
and cut out code leaving only the sys_ptrace.watchpoint_stress portion
that reproduces the problem.

The only special dependency is making sure libgtest-dev is installed

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).

This project is intended for demonstration purposes only. It is not
intended for use in a production environment.


