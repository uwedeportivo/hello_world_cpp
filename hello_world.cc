#include <iostream>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "greeting.pb.h"
#include "SQLiteCpp/include/SQLiteCpp/Database.h"
#include "cpp-peglib/peglib.h"
#include "httplib.h"
#include "openssl/evp.h"
#include "include/rocksdb/db.h"

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

const std::string kDBPath = "/tmp/rocksdb_simple_example";

int main() {
  const std::vector<std::string> v = {"foo", "bar", "baz"};
  const std::string s = absl::StrJoin(v, "-");

  greeting::Person person;
  person.set_name("John");
  person.set_id(32);
  person.set_email("john@john.com");


  std::cout << "Joined string: " << s << "\n";
  std::cout << person.SerializeAsString() << "\n";

  SQLite::Database sqlitedb("/tmp/example.db3", SQLite::OPEN_READWRITE|SQLite::OPEN_CREATE);

  peg::parser parser(R"(
    # Grammar for Calculator...
    Additive    <- Multiplicative '+' Additive / Multiplicative
    Multiplicative   <- Primary '*' Multiplicative / Primary
    Primary     <- '(' Additive ')' / Number
    Number      <- < [0-9]+ >
    %whitespace <- [ \t]*
  )");

  auto ss = computeSHA256("Hello world!");

  std::cout << "sha256: " << convertToHex<std::array<uint8_t, 32>>(ss) << "\n";

  httplib::Client cli("https://news.ycombinator.com");

  auto res = cli.Get("/user?id=uwehn");

  std::cout << "body: " << res->body << "\n";

  rocksdb::DB* db;
  rocksdb::Options options;
  // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
  options.IncreaseParallelism();
  options.OptimizeLevelStyleCompaction();
  // create the DB if it's not already present
  options.create_if_missing = true;

  // open DB
  rocksdb::Status rocks_status = rocksdb::DB::Open(options, kDBPath, &db);
  assert(rocks_status.ok());

  // Put key-value
  rocks_status = db->Put(rocksdb::WriteOptions(), "key1", "value");
  assert(rocks_status.ok());
  std::string value;
  // get value
  rocks_status = db->Get(rocksdb::ReadOptions(), "key1", &value);
  assert(rocks_status.ok());
  assert(value == "value");

  // atomically apply a set of updates
  {
    rocksdb::WriteBatch batch;
    batch.Delete("key1");
    batch.Put("key2", value);
    rocks_status = db->Write(rocksdb::WriteOptions(), &batch);
    assert(rocks_status.ok());
  }

  rocks_status = db->Get(rocksdb::ReadOptions(), "key1", &value);
  assert(rocks_status.IsNotFound());

  db->Get(rocksdb::ReadOptions(), "key2", &value);
  assert(value == "value");

  {
    rocksdb::PinnableSlice pinnable_val;
    db->Get(rocksdb::ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
    assert(pinnable_val == "value");
  }

  {
    std::string string_val;
    // If it cannot pin the value, it copies the value to its internal buffer.
    // The intenral buffer could be set during construction.
    rocksdb::PinnableSlice pinnable_val(&string_val);
    db->Get(rocksdb::ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
    assert(pinnable_val == "value");
    // If the value is not pinned, the internal buffer must have the value.
    assert(pinnable_val.IsPinned() || string_val == "value");
  }

  rocksdb::PinnableSlice pinnable_val;
  rocks_status = db->Get(rocksdb::ReadOptions(), db->DefaultColumnFamily(), "key1", &pinnable_val);
  assert(rocks_status.IsNotFound());
  // Reset PinnableSlice after each use and before each reuse
  pinnable_val.Reset();
  db->Get(rocksdb::ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
  assert(pinnable_val == "value");
  pinnable_val.Reset();
  // The Slice pointed by pinnable_val is not valid after this point

  delete db;


  return 0;
}
