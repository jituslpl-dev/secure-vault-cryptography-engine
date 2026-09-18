/**
 * @file logger.h
 * @brief Structured logging facility for SecureVault.
 *
 * Provides leveled logging (DEBUG, INFO, WARN, ERROR, FATAL) with
 * timestamp, source file, and line number. Output goes to stderr
 * by default. Can be redirected to a file or custom callback.
 *
 * @license MIT
 */

#ifndef SECURE_VAULT_LOGGER_H
#define SECURE_VAULT_LOGGER_H

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace securevault {

/**
 * @brief Log severity levels.
 */
enum class LogLevel : uint8_t {
    DEBUG = 0,
    INFO  = 1,
    WARN  = 2,
    ERROR = 3,
    FATAL = 4
};

/**
 * @brief Structured logger with severity levels and source location.
 *
 * Thread-safe. Output goes to stderr by default.
 * Set the minimum level to filter out lower-priority messages.
 */
class Logger {
public:
    /**
     * @brief Get the singleton logger instance.
     * @return Reference to the global Logger instance.
     */
    static Logger& instance();

    /**
     * @brief Set the minimum log level.
     * @param level Messages below this level are suppressed.
     */
    void setLevel(LogLevel level);

    /**
     * @brief Set the output stream.
     * @param stream FILE* to write to (default: stderr).
     */
    void setOutput(FILE* stream);

    /**
     * @brief Enable or disable timestamps in log output.
     * @param enable True to prefix each line with a timestamp.
     */
    void enableTimestamps(bool enable);

    /**
     * @brief Log a message at the specified level.
     * @param level Severity level.
     * @param file Source file name (__FILE__).
     * @param line Source line number (__LINE__).
     * @param fmt Printf-style format string.
     * @param ... Format arguments.
     */
    void log(LogLevel level, const char* file, int line, const char* fmt, ...);

    /**
     * @brief Convert a LogLevel to its string representation.
     * @param level The log level.
     * @return String label (e.g., "INFO", "ERROR").
     */
    static const char* levelToString(LogLevel level);

private:
    Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    LogLevel minLevel_;
    FILE* output_;
    bool timestamps_;
};

} // namespace securevault

/**
 * @brief Convenience macros for logging.
 * @{
 */
#define SV_LOG_DEBUG(fmt, ...) \
    ::securevault::Logger::instance().log(::securevault::LogLevel::DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define SV_LOG_INFO(fmt, ...) \
    ::securevault::Logger::instance().log(::securevault::LogLevel::INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define SV_LOG_WARN(fmt, ...) \
    ::securevault::Logger::instance().log(::securevault::LogLevel::WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define SV_LOG_ERROR(fmt, ...) \
    ::securevault::Logger::instance().log(::securevault::LogLevel::ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define SV_LOG_FATAL(fmt, ...) \
    ::securevault::Logger::instance().log(::securevault::LogLevel::FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/** @} */

#endif // SECURE_VAULT_LOGGER_H



