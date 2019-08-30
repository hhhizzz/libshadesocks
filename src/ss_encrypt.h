#ifndef SS_ENCRYPT_H__
#define SS_ENCRYPT_H__

#include <glog/logging.h>

#include <cryptlib.h>
using CryptoPP::InvalidArgument;
#include <string>
using std::string;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <aes.h>
using CryptoPP::AES;
using CryptoPP::byte;
using CryptoPP::SecByteBlock;

#include <gcm.h>
using CryptoPP::GCM;

#include <modes.h>
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;

#include "filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "md5.h"
using CryptoPP::Weak::MD5;

namespace shadesocks {
struct CipherInfo {
  int key_length;
  int iv_length;
};

const std::map<string, CipherInfo> cipher_map{
    {"aes-128-cfb", {16, 16}}, {"aes-192-cfb", {24, 16}},
    {"aes-256-cfb", {32, 16}}, {"aes-128-ctr", {16, 16}},
    {"aes-192-ctr", {24, 16}}, {"aes-256-ctr", {32, 16}},
    {"aes-128-gcm", {16, 16}}, {"aes-192-gcm", {24, 16}},
    {"aes-256-gcm", {32, 16}}};

class Cipher {
 public:
  virtual void SetKeyWithIV(SecByteBlock& key, SecByteBlock& iv) = 0;
  virtual SecByteBlock GetKey() = 0;
  virtual SecByteBlock GetIv() = 0;

  virtual SecByteBlock encrypt(const string&) = 0;
  virtual SecByteBlock encrypt(const SecByteBlock&) = 0;

  virtual SecByteBlock decrypt(const string&) = 0;
  virtual SecByteBlock decrypt(const SecByteBlock&) = 0;

  virtual ~Cipher() {}
};

template <typename EncryptMode>
class ShadeCipher : public Cipher {
 private:
  typename EncryptMode::Encryption encryption;
  typename EncryptMode::Decryption decryption;
  SecByteBlock key;
  SecByteBlock iv;

 public:
  ShadeCipher(SecByteBlock& key, SecByteBlock& iv) {
    this->SetKeyWithIV(key, iv);
  }

  void SetKeyWithIV(SecByteBlock& key, SecByteBlock& iv) {
    this->key = key;
    this->iv = iv;
    this->encryption.SetKeyWithIV(key, key.size(), iv, iv.size());
    this->decryption.SetKeyWithIV(key, key.size(), iv, iv.size());
  }
  SecByteBlock GetKey() { return this->key; }
  SecByteBlock GetIv() { return this->iv; }

  SecByteBlock encrypt(const string& input) {
    SecByteBlock bytes = SecByteBlock((byte*)input.data(), input.size());
    return this->encrypt(bytes);
  }
  SecByteBlock encrypt(const SecByteBlock& input) {
    SecByteBlock output(input.size());
    this->encryption.ProcessData(output, input, input.size());
    return output;
  }

  SecByteBlock decrypt(const string& input) {
    SecByteBlock bytes = SecByteBlock((byte*)input.data(), input.size());
    return this->decrypt(bytes);
  }
  SecByteBlock decrypt(const SecByteBlock& input) {
    SecByteBlock output(input.size());
    this->decryption.ProcessData(output, input, input.size());
    return output;
  }

  ~ShadeCipher() {}
};

class Util {
 public:
  static string HexToString(const SecByteBlock& input);
  static SecByteBlock StringToHex(const string& input);
  // Returns md5 padding password in bytes
  static SecByteBlock PasswordToKey(const string& password, size_t key_length);
  static SecByteBlock Md5Sum(const SecByteBlock& input);
  static std::unique_ptr<Cipher> getEncryption(const string& method,
                                               SecByteBlock& key,
                                               SecByteBlock& iv);
  static std::unique_ptr<Cipher> getEncryption(const string& method);
  static SecByteBlock RandomBlock(int size);
};

}  // namespace shadesocks
#endif