#include "ss_test.h"

TEST(EncryptTest, HandleStringToHex) {
  string input = "FFEEDDCCBBAA99887766554433221100";
  auto acutal = shadesocks::Util::StringToHex(input);

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
  string actual = shadesocks::Util::HexToString(input);
  LOG(INFO) << "the result is " << actual;
  EXPECT_EQ(actual, "FFEEDDCCBBAA99887766554433221100");
}

TEST(EncryptTest, HandleMD5) {
  std::string msg = "foobar";
  byte expected[]{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91,
                  0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f};

  std::string digest;
  auto bytes = (byte*) (msg.data());
  SecByteBlock secBytes(bytes, msg.size());
  auto output = shadesocks::Util::Md5Sum(secBytes);
  LOG(INFO) << "the result is " << shadesocks::Util::HexToString(output);
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i], expected[i]);
  }
}

TEST(EncryptTest, HandlePassword) {
  auto bytes = shadesocks::Util::PasswordToKey("foobar", 32);
  byte expected[]{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91,
                  0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f,
                  0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d,
                  0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf};
  LOG(INFO) << shadesocks::Util::HexToString(bytes);
  for (int i = 0; i < bytes.size(); i++) {
    EXPECT_EQ(bytes[i], expected[i]);
  }
}

void test_encrypt(const string& method) {
  std::unique_ptr<shadesocks::Cipher> cipher =
      shadesocks::Util::getEncryption(method);

  string encoded;
  SecByteBlock key = cipher->GetKey();
  SecByteBlock iv = cipher->GetIv();
  encoded = shadesocks::Util::HexToString(key);
  LOG(INFO) << "the key is : " + encoded;
  encoded = shadesocks::Util::HexToString(iv);
  LOG(INFO) << "the iv  is : " + encoded;

  std::string plain_text = "Hello! How are you.";
  LOG(INFO) << "plain text is " << plain_text;

  //////////////////////////////////////////////////////////////////////////
  // Encrypt

  auto encryptData = cipher->encrypt(plain_text);
  LOG(INFO) << "encrypt byte is " << shadesocks::Util::HexToString(encryptData);

  //////////////////////////////////////////////////////////////////////////
  // Decrypt
  auto decryptData = cipher->decrypt(encryptData);
  LOG(INFO) << "decrypt byte is " << shadesocks::Util::HexToString(decryptData);
  LOG(INFO) << "decrypt text is "
            << string(reinterpret_cast<char*>(decryptData.data()),
                      decryptData.size());
  for (int i = 0; i < decryptData.size(); i++) {
    EXPECT_EQ(plain_text[i], decryptData[i]);
  }
}

TEST(EncryptTest, HandleAES) {
  string method = "aes-128-cfb";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-192-cfb";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-256-cfb";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-128-ctr";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-192-ctr";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-256-ctr";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-128-gcm";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-192-gcm";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);

  method = "aes-256-gcm";
  LOG(INFO) << "start to test method " + method;
  test_encrypt(method);
}

int main(int argc, char** argv) {
  FLAGS_colorlogtostderr = 1;
  FLAGS_stderrthreshold = 0;
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
