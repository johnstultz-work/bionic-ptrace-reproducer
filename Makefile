all:
	g++ sys_ptrace_test.cpp -o ptrace-test -lgtest -lpthread

clean:
	rm ptrace-test
