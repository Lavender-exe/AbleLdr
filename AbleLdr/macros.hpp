#ifndef MACROS_HPP
#define MACROS_HPP

#ifdef _DEBUG
#define printf(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define printf(fmt, ...) (0)
#endif

#endif