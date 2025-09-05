//By AlSch092 @ github
#include "../include/Utility.hpp"

/**
 * @brief Generates a random string of specified length
 *
 * @param length size of the string to generate
 * @return string object containing the random string
 *
 * @usage
 * string randomStr = Utility::GenerateRandomString(16);
 */
std::string Utility::GenerateRandomString(__in const int length)
{
    if (length <= 0) return "";

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    const size_t charsetSize = strlen(charset);

    std::string randomString;
    randomString.reserve(length);

    static bool seedInitialized = false;
    if (!seedInitialized) 
    {
        srand(static_cast<unsigned int>(time(nullptr)));
        seedInitialized = true;
    }

    for (int i = 0; i < length; ++i) 
    {
        randomString.push_back(charset[rand() % charsetSize]);
    }

    return randomString;
}

/**
 * @brief Generates a random wide string of specified length
 *
 * @param length size of the string to generate
 * @return wide string object containing the random string
 *
 * @usage
 * wstring randomStr = Utility::GenerateRandomWString(16);
 */
std::wstring Utility::GenerateRandomWString(__in const int length)
{
    if (length <= 0) return L"";

    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    const size_t charsetSize = wcslen(charset);

    std::wstring randomString;
    randomString.reserve(length);

    static bool seedInitialized = false;
    if (!seedInitialized) 
    {
        srand(static_cast<unsigned int>(time(nullptr)));
        seedInitialized = true;
    }

    for (int i = 0; i < length; ++i) 
    {
        randomString.push_back(charset[rand() % charsetSize]);
    }

    return randomString;
}

/*
 * @brief Converts a string to lowercase in-place
 *
 * @param str Pointer to the string to convert
 *
 * @usage
 * char myString[] = "Hello World!";
 * Utility::str_to_lower(myString);
 */ 
void Utility::str_to_lower(__inout char* str)
{
    while (*str)
    {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

/*
 * @brief Finds the first occurrence of a substring in a string, case-insensitively
 *
 * @param haystack The string to search in
 * @param needle The substring to search for
 * @return Pointer to the first occurrence of needle in haystack, or nullptr if not found
 *
 * @usage
 * char* result = Utility::strstr_case_insensitive("Hello World", "world");
 */ 
char* Utility::strstr_case_insensitive(__in const char* haystack, __in const char* needle)
{
    if (!haystack || !needle)
    {
        return nullptr;
    }

    if (!*needle)
    {
        return (char*)haystack;
    }

    char* haystack_lower = _strdup(haystack);
    char* needle_lower = _strdup(needle);

    if (!haystack_lower || !needle_lower)
    {
        free(haystack_lower);
        free(needle_lower);
        return nullptr;
    }

    for (char* p = haystack_lower; *p; ++p)
    {
        *p = std::tolower(*p);
    }

    for (char* p = needle_lower; *p; ++p)
    {
        *p = std::tolower(*p);
    }

    char* result = strstr(haystack_lower, needle_lower);
    char* final_result = result ? (char*)(haystack + (result - haystack_lower)) : nullptr;
    free(haystack_lower);
    free(needle_lower);

    return final_result;
}

/*
 * @brief Compares two strings case-insensitively
 *
 * @param s1 First string to compare
 * @param s2 Second string to compare
 * @return true if the strings are equal, false otherwise
 *
 * @usage
 * bool isEqual = Utility::strcmp_insensitive("Hello", "hello");
 */ 
bool Utility::strcmp_insensitive(__in const char* s1, __in const char* s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    int len1 = (int)strlen(s1);
    int len2 = (int)strlen(s2);

    if (len1 != len2)
        return false;

    for (int i = 0; i < len1; i++)
    {
        if (tolower(s1[i]) != tolower(s2[i]))
        {
            return false;
        }
    }

    return true;
}

/*
 * @brief Compares two wide strings case-insensitively
 *
 * @param s1 First wide string to compare
 * @param s2 Second wide string to compare
 * @return true if the wide strings are equal, false otherwise
 *
 * @usage
 * bool isEqual = Utility::wcscmp_insensitive(L"Hello", L"hello");
 */
bool Utility::wcscmp_insensitive(__in const wchar_t* s1, __in const wchar_t* s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    int len1 = (int)wcslen(s1);
    int len2 = (int)wcslen(s2);

    if (len1 != len2)
        return false;

    for (int i = 0; i < len1; i++)
    {
        if (towlower(s1[i]) != towlower(s2[i]))
        {
            return false;
        }
    }

    return true;
}

/*
 * @brief Converts a wide string to a standard string
 *
 * @param wstr Wide string to convert
 * @return Standard string representation of the wide string
 *
 * @usage
 * std::string str = Utility::ConvertWStringToString(L"Hello World");
 */ 
std::string Utility::ConvertWStringToString(__in const std::wstring& wstr)
{
    std::locale loc("");
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

/*
 * @brief Converts a standard string to a wide string
 *
 * @param str Standard string to convert
 * @return Wide string representation of the standard string
 *
 * @usage
 * std::wstring wstr = Utility::ConvertStringToWString("Hello World");
 */
std::wstring Utility::ConvertStringToWString(__in const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

/*
 * @brief Splits a string by spaces and returns a vector of strings
 *
 * @param str Pointer to the string to split
 * @return Vector of strings containing the split parts
 *
 * @usage
 * char myString[] = "Hello World from Utility";
 * std::vector<std::string> parts = Utility::splitStringBySpace(myString);
 */ 
std::vector<std::string> Utility::splitStringBySpace(__in char* str)
{
    std::vector<std::string> result;
    char* token = strtok(str, " ");
    while (token != nullptr)
    {
        result.push_back(std::string(token));
        token = strtok(nullptr, " ");
    }
    return result;
}

/*
 * @brief Adds a unique string to a list if it does not already exist
 *
 * @param strList Reference to the list of strings
 * @param str String to add
 *
 * @usage
 * std::list<std::string> myList;
 * Utility::addUniqueString(myList, "Hello");
 */
void Utility::addUniqueString(__inout std::list<std::string>& strList, __in const std::string& str)
{
    if (find(strList.begin(), strList.end(), str) == strList.end())
    {
        strList.push_back(str);
    }
}

/*
 * @brief Checks if all elements in list1 are present in list2
 *
 * @param list1 First list of strings
 * @param list2 Second list of strings
 * @return true if all elements in list1 are in list2, false otherwise
 *
 * @usage
 * std::list<std::string> list1 = {"Hello", "World"};
 * std::list<std::string> list2 = {"Hello", "World", "!"};
 * bool result = Utility::areAllElementsInList(list1, list2);
 */
bool Utility::areAllElementsInList(__in const std::list<std::string>& list1, __in const std::list<std::string>& list2)
{
    for (const auto& str : list1)
    {
        if (std::find(list2.begin(), list2.end(), str) == list2.end())
        {
            return false; //an element in list1 is not in list2
        }
    }
    return true; //elements in list1 are in list2
}

/*
 * @brief Converts a wide string to lowercase
 *
 * @param str Wide string to convert
 * @return Lowercase wide string
 *
 * @usage
 * std::wstring lowerStr = Utility::ToLower(L"Hello World");
 */
std::wstring Utility::ToLower(__in const std::wstring& str) 
{
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](wchar_t ch) { return std::towlower(ch); });
    return lowerStr;
}

/*
 * @brief Checks if a wide string contains another wide string, case-insensitively
 *
 * @param haystack The wide string to search in
 * @param needle The wide string to search for
 * @return true if needle is found in haystack, false otherwise
 *
 * @usage
 * bool found = Utility::ContainsWStringInsensitive(L"Hello World", L"world");
 */ 
bool Utility::ContainsWStringInsensitive(__in const std::wstring& haystack, __in const std::wstring& needle) 
{
    std::wstring lowerHaystack = ToLower(haystack);
    std::wstring lowerNeedle = ToLower(needle); //convert both strings to lowercase, check if the needle is in the haystack
    return lowerHaystack.find(lowerNeedle) != std::wstring::npos;
}


/*
 * @brief Modifies an NT path to being it's corresponding DOS path (ex. \\??\... to C:\)
 *
 * @param ntPath   input path in NT format
 * @return wstring value of a DOS path from the input NT path
 *
 * @usage
 * std::wstring dosPath = Utility::NtPathToDosPath(L"\\\\??\\C:\\WINDOWS\\System32\\test.txt");
 */
std::wstring Utility::NtPathToDosPath(const std::wstring& ntPath)
{
    if (ntPath.empty()) return L"";

    WCHAR drives[512];
    if (!GetLogicalDriveStringsW(sizeof(drives) / sizeof(WCHAR), drives))
        return ntPath;

    WCHAR deviceName[MAX_PATH];
    WCHAR* drive = drives;

    while (*drive)
    {
        if (QueryDosDeviceW(drive, deviceName, MAX_PATH))
        {
            size_t len = wcslen(deviceName);
            if (_wcsnicmp(ntPath.c_str(), deviceName, len) == 0)
            {
                std::wstring dosPath = drive;
                dosPath.pop_back(); // remove trailing '\'
                dosPath += ntPath.substr(len);
                return dosPath;
            }
        }
        drive += wcslen(drive) + 1;
    }
    return ntPath;
}