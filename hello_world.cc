#include <iostream>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "greeting.pb.h"

int main() {
  const std::vector<std::string> v = {"foo", "bar", "baz"};
  const std::string s = absl::StrJoin(v, "-");

  greeting::Person person;
  person.set_name("John");
  person.set_id(32);
  person.set_email("john@john.com");


  std::cout << "Joined string: " << s << "\n";
  std::cout << person.SerializeAsString() << "\n";

  return 0;
}
