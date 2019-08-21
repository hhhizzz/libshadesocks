#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss_encrypt.h"

#include <iostream>
using std::cout;
using std::endl;


TEST(EncryptTest, HandleNoneZeroInput) {
  AutoSeededRandomPool rnd;

  // Generate a random key
  SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);  // length is 16
  rnd.GenerateBlock(key, key.size());

  // Generate a random IV
  SecByteBlock iv(AES::BLOCKSIZE);  // length is 16
  rnd.GenerateBlock(iv, iv.size());

  string encoded;
  encoded = shadesocks::ShadeEncrypt::HexToString(key,key.size());
  cout << "the key is : " + encoded << endl;
  encoded = shadesocks::ShadeEncrypt::HexToString(iv,iv.size());
  cout << "the iv is : " + encoded << endl;

  byte plainText[] = "Hello! How are you.";
  size_t messageLen = std::strlen((char*)plainText) + 1;

  //////////////////////////////////////////////////////////////////////////
  // Encrypt

  CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
  cfbEncryption.ProcessData(plainText, plainText, messageLen);

  //////////////////////////////////////////////////////////////////////////
  // Decrypt

  CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
  cfbDecryption.ProcessData(plainText, plainText, messageLen);
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
