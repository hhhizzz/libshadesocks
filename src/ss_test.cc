#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss.h"
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CFB_Mode;

TEST(FooTest, HandleNoneZeroInput) {
  LOG(ERROR) << "start to test";
  EXPECT_EQ(2, Foo(4, 10));
  EXPECT_EQ(6, Foo(30, 18));
}
TEST(CryptoppTest, HandleNoneZeroInput) {
  AutoSeededRandomPool prng;

  CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  CryptoPP::byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  string plain = "CFB Mode Test";
  string cipher, encoded, recovered;

  /*********************************\
  \*********************************/

  // Pretty print key
  encoded.clear();
  StringSource(key, sizeof(key), true,
               new HexEncoder(new StringSink(encoded))  // HexEncoder
  );                                                    // StringSource
  cout << "key: " << encoded << endl;

  // Pretty print iv
  encoded.clear();
  StringSource(iv, sizeof(iv), true,
               new HexEncoder(new StringSink(encoded))  // HexEncoder
  );                                                    // StringSource
  cout << "iv: " << encoded << endl;

  /*********************************\
  \*********************************/

  try {
    cout << "plain text: " << plain << endl;

    CFB_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    // CFB mode must not use padding. Specifying
    //  a scheme will result in an exception
    StringSource(plain, true,
                 new StreamTransformationFilter(
                     e,
                     new StringSink(cipher))  // StreamTransformationFilter
    );                                        // StringSource
  } catch (const CryptoPP::Exception& e) {
    cerr << e.what() << endl;
    exit(1);
  }

  /*********************************\
  \*********************************/

  // Pretty print
  encoded.clear();
  StringSource(cipher, true,
               new HexEncoder(new StringSink(encoded))  // HexEncoder
  );                                                    // StringSource
  cout << "cipher text: " << encoded << endl;

  /*********************************\
  \*********************************/

  try {
    CFB_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true,
                   new StreamTransformationFilter(
                       d,
                       new StringSink(recovered))  // StreamTransformationFilter
    );                                             // StringSource

    cout << "recovered text: " << recovered << endl;
  } catch (const CryptoPP::Exception& e) {
    cerr << e.what() << endl;
    exit(1);
  }
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}