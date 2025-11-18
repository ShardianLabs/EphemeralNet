#include <filesystem>
#include <iostream>

int main() {
    std::filesystem::path p("foo/");
    std::cout << "Original: " << p << ", has_filename: " << p.has_filename() << std::endl;
    
    std::filesystem::path abs = std::filesystem::absolute(p);
    std::cout << "Absolute: " << abs << ", has_filename: " << abs.has_filename() << std::endl;
    
    std::filesystem::path p2("foo\\");
    std::cout << "Original backslash: " << p2 << ", has_filename: " << p2.has_filename() << std::endl;
    
    std::filesystem::path abs2 = std::filesystem::absolute(p2);
    std::cout << "Absolute backslash: " << abs2 << ", has_filename: " << abs2.has_filename() << std::endl;

    std::filesystem::path p3("foo/.");
    std::cout << "Dot: " << p3 << ", has_filename: " << p3.has_filename() << ", filename: " << p3.filename() << std::endl;
    
    std::filesystem::path p4("foo/..");
    std::cout << "DotDot: " << p4 << ", has_filename: " << p4.has_filename() << ", filename: " << p4.filename() << std::endl;

    return 0;
}
