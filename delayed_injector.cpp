#include <windows.h>
#include <iostream>
#include <filesystem>

#include "config.hpp"
#include "pe_file.hpp"
#include "injector.hpp"

using namespace std;

int main() {
  cout << "/+/ Delayed loader started. Author: Receiver" << endl;

  c_config config;
  try {
    c_injector injector;
    auto path = filesystem::current_path();
    path += "\\" + config.plugins_path;

    /*bool once = true;
    do {
      if (once) {
        cout << "/// Waiting for process: " << config.process_name << endl;
        once = false;
      }
    } while (!injector.set_process(config.process_name));*/

    cout << "/+/ Process opened. Start loading plugins..." << endl;

    Sleep(config.inject_delay);

    if (!filesystem::exists(path)) {
      filesystem::create_directory(path);
    }

    filesystem::recursive_directory_iterator iterator{path};
    for (auto& entry : iterator) {
      if (entry.is_directory()) continue;

      std::string name{entry.path().string()};
      name = name.substr(name.find_last_of('\\') + 1);

      cout << "/// Injecting: " << name << " -> ";

      try {
        c_pe_file file{entry.path().string()};
        injector.inject(entry.path().string());

        cout << "Success" << endl;
      } catch (c_inject_error& error) {
        cout << error.what() << endl;
      } catch (runtime_error& error) {
        cout << error.what() << endl;
      }
    }
  } catch (runtime_error& error) {
    cout << "/-/ Failed to receive: " << error.what() << endl;
  }

  system("pause");
}