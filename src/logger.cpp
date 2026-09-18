/**
 * @file logger.cpp
 * @brief Implementation of the SecureVault structured logger.
 *
 * @license MIT
 */

#include "logger.h"
#include <cstdarg>
#include <ctime>

namespace securevault {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

Logger::Logger()
    : minLevel_(LogLevel::WARN)
    , output_(stderr)
    , timestamps_(true) {
}

void Logger::setLevel(LogLevel level) {
    minLevel_ = level;
}

void Logger::setOutput(FILE* stream) {
    output_ = stream;
}

void Logger::enableTimestamps(bool enable) {
    timestamps_ = enable;
}

const char* Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default:               return "UNKNOWN";
    }
}

void Logger::log(LogLevel level, const char* file, int line, const char* fmt, ...) {
    if (static_cast<uint8_t>(level) < static_cast<uint8_t>(minLevel_)) {
        return;
    }

    // Extract just the filename from the full path
    const char* filename = file;
    const char* lastSep = strrchr(file, '/');
#ifdef _WIN32
    const char* lastBackslash = strrchr(file, '\\');
    if (lastBackslash && (!lastSep || lastBackslash > lastSep)) {
        lastSep = lastBackslash;
    }
#endif
    if (lastSep) {
        filename = lastSep + 1;
    }

    // Timestamp
    if (timestamps_) {
        time_t now = time(nullptr);
        struct tm tm_info;
#ifdef _WIN32
        localtime_s(&tm_info, &now);
#else
        localtime_r(&now, &tm_info);
#endif
        char timeBuf[32];
        strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tm_info);
        fprintf(output_, "[%s] ", timeBuf);
    }

    // Level and source
    fprintf(output_, "%-5s [%s:%d] ", levelToString(level), filename, line);

    // Message
    va_list args;
    va_start(args, fmt);
    vfprintf(output_, fmt, args);
    va_end(args);

    fprintf(output_, "\n");
    fflush(output_);
}

} // namespace securevault



