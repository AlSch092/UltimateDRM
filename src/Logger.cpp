//AlSch092 @ Github
#include "../include/Logger.hpp"

bool Logger::enableLogging = true;
std::string Logger::logFileName = "UltimateDRM.log";
std::mutex Logger::consoleMutex;
