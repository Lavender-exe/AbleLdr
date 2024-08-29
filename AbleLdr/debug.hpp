#ifndef DEBUG_HPP
#define DEBUG_HPP

#pragma region [colour codes]

#define COLOUR_DEFAULT "\033[0m"
#define COLOUR_BOLD "\033[1m"
#define COLOUR_UNDERLINE "\033[4m"
#define COLOUR_NO_UNDERLINE "\033[24m"
#define COLOUR_NEGATIVE "\033[7m"
#define COLOUR_POSITIVE "\033[27m"
#define COLOUR_BLACK "\033[30m"
#define COLOUR_RED "\033[31m"
#define COLOUR_GREEN "\033[32m"
#define COLOUR_YELLOW "\033[33m"
#define COLOUR_BLUE "\033[34m"
#define COLOUR_MAGENTA "\033[35m"
#define COLOUR_CYAN "\033[36m"
#define COLOUR_LIGHTGRAY "\033[37m"
#define COLOUR_DARKGRAY "\033[90m"
#define COLOUR_LIGHTRED "\033[91m"
#define COLOUR_LIGHTGREEN "\033[92m"
#define COLOUR_LIGHTYELLOW "\033[93m"
#define COLOUR_LIGHTBLUE "\033[94m"
#define COLOUR_LIGHTMAGENTA "\033[95m"
#define COLOUR_LIGHTCYAN "\033[96m"
#define COLOUR_WHITE "\033[97m"

#pragma endregion

#pragma region [dprintf]

#if _DEBUG
#include <stdio.h>
#define dprintf(fmt, ...)       printf(fmt, ##__VA_ARGS__)
#define LOG_SUCCESS(fmt, ...)   printf(COLOUR_BOLD COLOUR_GREEN   "[+]" COLOUR_DEFAULT " [%s] " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)      printf(COLOUR_BOLD COLOUR_BLUE    "[*]" COLOUR_DEFAULT " [%s] " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)     printf(COLOUR_BOLD COLOUR_RED     "[!]" COLOUR_DEFAULT " [%s] " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)     printf(COLOUR_BOLD COLOUR_MAGENTA "[D]" COLOUR_DEFAULT " [%s] " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define dprintf(fmt, ...)     (0)
#define LOG_SUCCESS(fmt, ...) (0)
#define LOG_INFO(fmt, ...)    (0)
#define LOG_ERROR(fmt, ...)   (0)
#define LOG_DEBUG(fmt, ...)   (0)
#endif

#pragma endregion

#endif