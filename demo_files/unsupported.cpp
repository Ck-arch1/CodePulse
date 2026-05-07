#include <cstdlib>
#include <iostream>

int main() {
    const char* password = "demo-secret";
    std::string host;
    std::cin >> host;
    system(("ping " + host).c_str());
    // TODO: replace shell execution before release
    return 0;
}
