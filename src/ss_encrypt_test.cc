#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss_encrypt.h"

#include <iostream>
using std::cout;
using std::endl;

TEST(EncryptTest, HandleStringToHex) {
  string input = "FFEEDDCCBBAA99887766554433221100";
  auto acutal = shadesocks::ShadeEncrypt::StringToHex(input);

  byte expected[]{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
  for (int i = 0; i < input.size() / 2; i++) {
    EXPECT_EQ(acutal[i], expected[i]);
  }
}

TEST(EncryptTest, HandleHexToString) {
  byte bytes[]{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
               0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
  SecByteBlock input(bytes, sizeof(bytes));
  string actual = shadesocks::ShadeEncrypt::HexToString(input);
  cout << "the result is " << actual << endl;
  EXPECT_EQ(actual, "FFEEDDCCBBAA99887766554433221100");
}

TEST(EncryptTest, HandleMD5) {
  std::string msg = "foobar";
  byte expected[]{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91,
                  0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f};

  std::string digest;
  auto bytes = (byte*)(msg.data());
  SecByteBlock secBytes(bytes, msg.size());
  auto output = shadesocks::ShadeEncrypt::Md5Sum(secBytes);
  cout << "the result is " << shadesocks::ShadeEncrypt::HexToString(output)
       << endl;
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i], expected[i]);
  }
}

TEST(EncryptTest, HandlePassword) {
  auto bytes = shadesocks::ShadeEncrypt::PasswordToKey("foobar", 32);
  byte expected[]{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91,
                  0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f,
                  0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d,
                  0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf};
  cout << shadesocks::ShadeEncrypt::HexToString(bytes) << endl;
  for (int i = 0; i < bytes.size(); i++) {
    EXPECT_EQ(bytes[i], expected[i]);
  }
}

TEST(EncryptTest, HandleAESCFB) {
  AutoSeededRandomPool rnd;

  // Generate a random key
  SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);  // length is 16
  rnd.GenerateBlock(key, key.size());

  // Generate a random IV
  SecByteBlock iv(AES::BLOCKSIZE);  // length is 16
  rnd.GenerateBlock(iv, iv.size());

  string encoded;
  encoded = shadesocks::ShadeEncrypt::HexToString(key);
  cout << "the key is : " + encoded << endl;
  encoded = shadesocks::ShadeEncrypt::HexToString(iv);
  cout << "the iv  is : " + encoded << endl;

  std::string plain_text = "Hello! How are you.";
  cout << "plain text is " << plain_text << endl;

  //////////////////////////////////////////////////////////////////////////
  // Encrypt
  shadesocks::ShadeEncryptCFB encrypt(key, iv);
  auto encryptData = encrypt.encrypt(plain_text);
  cout << "encrypt byte is "
       << shadesocks::ShadeEncrypt::HexToString(encryptData) << endl;

  //////////////////////////////////////////////////////////////////////////
  // Decrypt
  auto decryptData = encrypt.decrypt(encryptData);
  cout << "decrypt byte is "
       << shadesocks::ShadeEncrypt::HexToString(decryptData) << endl;
  cout << "decrypt text is "
       << string((char*)decryptData.data(), decryptData.size()) << endl;
  for (int i = 0; i < decryptData.size(); i++) {
    EXPECT_EQ(plain_text[i], decryptData[i]);
  }
}

int main(int argc, char** argv) {
  FLAGS_colorlogtostderr = 1;
  FLAGS_stderrthreshold = 0;
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
