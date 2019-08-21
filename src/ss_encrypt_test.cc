#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss_encrypt.h"

#include <iostream>
using std::cout;
using std::endl;

TEST(EncryptTest, HandleStringToHex) {
  string input = "FFEEDDCCBBAA99887766554433221100";
  auto acutal = shadesocks::ShadeEncrypt::StringToHex(input, input.size());

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
  string actual = shadesocks::ShadeEncrypt::HexToString(input, input.size());
  EXPECT_EQ(actual, "FFEEDDCCBBAA99887766554433221100");
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
  encoded = shadesocks::ShadeEncrypt::HexToString(key, key.size());
  cout << "the key is : " + encoded << endl;
  encoded = shadesocks::ShadeEncrypt::HexToString(iv, iv.size());
  cout << "the iv  is : " + encoded << endl;

  byte plain_text[] = "Hello! How are you.";
  size_t message_len = std::strlen((char*)plain_text) + 1;
  cout << "plain text is   " << plain_text << endl;

  //////////////////////////////////////////////////////////////////////////
  // Encrypt
  byte encryption_data[message_len];
  CFB_Mode<AES>::Encryption cfb_encryption(key, key.size(), iv);
  cfb_encryption.ProcessData(encryption_data, plain_text, message_len);

  encoded = shadesocks::ShadeEncrypt::HexToString(encryption_data, message_len);
  cout << "encrypt byte is " << encoded << endl;

  //////////////////////////////////////////////////////////////////////////
  // Decrypt
  byte decryption_data[message_len];
  CFB_Mode<AES>::Decryption cfb_decryption(key, key.size(), iv);
  cfb_decryption.ProcessData(decryption_data, encryption_data, message_len);
  encoded = shadesocks::ShadeEncrypt::HexToString(decryption_data, message_len);
  cout << "decrypt byte is " << encoded << endl;

  for (int i = 0; i < message_len; i++) {
    EXPECT_EQ(plain_text[i], decryption_data[i]);
  }
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
