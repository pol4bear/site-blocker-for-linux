#include <iostream>
#include "harmfulsiteblocker.h"

using namespace std;

void OnReceive(string message){
    cout << "[+] " << message << "\n";
}

int main(int argc, char *argv[])
{
    if(argc < 3) {
        cerr << "Usage: " << argv[0] << " [Queue number] [Harmful list]\n";
        exit(1);
    }

    try {
        uint16_t queue_number = stoi(argv[1]);

        HarmfulSiteBlocker blocker(argv[2]);
        blocker.SetOnEventOccured(OnReceive);

        cout << "[i] Starting Harmful Site Blocker...\n";
        blocker.Start(queue_number);
        cout << "[i] Harmful Site Blocker Started\n";

        int receive;
        while ((receive = blocker.Receive()) >= 0 || (receive < 0 && errno == ENOBUFS)) {
            if (receive < 0) {
                cerr << "[-] Packet losed\n";
                continue;
            }

            blocker.Handle();
        }

        blocker.Stop();
    }
    catch (invalid_argument e){
        cerr << "[!] " << e.what() << "\n";
    }
    catch (runtime_error e) {
        cerr << "[!] " << e.what() << "\n";
    }

    return 0;
}
