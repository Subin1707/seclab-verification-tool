#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

int guarded_operation(int value) {
    if (value == 13) {
#ifdef _WIN32
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        RaiseException(0xC0000005, EXCEPTION_NONCONTINUABLE, 0, 0);
#else
        raise(SIGABRT);
#endif
    }
    return value;
}
