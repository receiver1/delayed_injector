#pragma once

#include <string>
#include <fstream>

class c_config {
 public:
  std::string process_name{"gta_sa.exe"};
  std::string plugins_path{"plugins"};
  int inject_delay = 0;

  bool load() {
    std::ifstream file{"config.ini"};
    if (file.is_open()) {
      std::string key, value;
      while (file >> key >> value) {
        if (key == "process_name")
          process_name = value;
        else if (key == "plugins_path")
          plugins_path = value;
        else if (key == "inject_delay")
          inject_delay = std::stoi(value);
      }
      file.close();
      return true;
    }
    return false;
  }

  void save() {
    std::ofstream file{"config.ini"};
    if (file.is_open()) {
      file << "process_name " << process_name << std::endl;
      file << "plugins_path " << plugins_path << std::endl;
      file << "inject_delay " << inject_delay << std::endl;
      file.close();
    }
  }

  c_config() {
    if (!load()) {
      save();
    }
  }
};