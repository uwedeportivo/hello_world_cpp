#include <iostream>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "greeting.pb.h"
#include "SQLiteCpp/include/SQLiteCpp/Database.h"
#include "cpp-peglib/peglib.h"
#include "marl/include/marl/defer.h"
#include "marl/include/marl/event.h"
#include "marl/include/marl/scheduler.h"
#include "marl/include/marl/waitgroup.h"
#include "openssl/evp.h"


template<typename T>
std::string convertToHex(const T& binaryResult)
{
  std::ostringstream ss;
  ss << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < binaryResult.size(); ++i) {
    ss << std::setw(2) << static_cast<unsigned>(binaryResult.at(i));
  }

  return ss.str();
}

std::array<uint8_t, 32> computeSHA256(const std::string& input) {
  std::array<uint8_t, 32> hash{};

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  const EVP_MD* md = EVP_sha256();

  EVP_DigestInit_ex(mdctx, md, nullptr);
  EVP_DigestUpdate(mdctx, input.c_str(), input.length());
  EVP_DigestFinal_ex(mdctx, hash.data(), nullptr);

  EVP_MD_CTX_free(mdctx);
  return hash;
}

std::string computeSHA256Hex(const std::string& input) {
  auto hash = computeSHA256(input);
  return convertToHex(hash);
}

int main() {
  const std::vector<std::string> v = {"foo", "bar", "baz"};
  const std::string s = absl::StrJoin(v, "-");

  greeting::Person person;
  person.set_name("John");
  person.set_id(32);
  person.set_email("john@john.com");


  std::cout << "Joined string: " << s << "\n";
  std::cout << person.SerializeAsString() << "\n";

  SQLite::Database db("/tmp/example.db3", SQLite::OPEN_READWRITE|SQLite::OPEN_CREATE);

  peg::parser parser(R"(
    # Grammar for Calculator...
    Additive    <- Multiplicative '+' Additive / Multiplicative
    Multiplicative   <- Primary '*' Multiplicative / Primary
    Primary     <- '(' Additive ')' / Number
    Number      <- < [0-9]+ >
    %whitespace <- [ \t]*
  )");

  marl::Scheduler scheduler(marl::Scheduler::Config::allCores());
  scheduler.bind();
  defer(scheduler.unbind());  // Automatically unbind before returning.

  constexpr int numTasks = 10;

  // Create an event that is manually reset.
  marl::Event sayHello(marl::Event::Mode::Manual);

  // Create a WaitGroup with an initial count of numTasks.
  marl::WaitGroup saidHello(numTasks);

  // Schedule some tasks to run asynchronously.
  for (int i = 0; i < numTasks; i++) {
    // Each task will run on one of the 4 worker threads.
    marl::schedule([=] {  // All marl primitives are capture-by-value.
      // Decrement the WaitGroup counter when the task has finished.
      defer(saidHello.done());

      printf("Task %d waiting to say hello...\n", i);

      // Blocking in a task?
      // The scheduler will find something else for this thread to do.
      sayHello.wait();

      printf("Hello from task %d!\n", i);
    });
  }

  sayHello.signal();  // Unblock all the tasks.

  saidHello.wait();  // Wait for all tasks to complete.

  printf("All tasks said hello.\n");

  auto ss = computeSHA256("Hello world!");

  std::cout << "sha256: " << convertToHex<std::array<uint8_t, 32>>(ss) << "\n";

  return 0;
}
