#ifndef SHADESOCKS_SRC_SS_ENCRYPT_H_
#define SHADESOCKS_SRC_SS_ENCRYPT_H_

#include <glog/logging.h>

#include <cryptlib.h>
using CryptoPP::InvalidArgument;

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

const std::map<std::string, CipherInfo> cipher_map{
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

  virtual SecByteBlock encrypt(const std::string&) = 0;
  virtual SecByteBlock encrypt(const SecByteBlock&) = 0;

  virtual SecByteBlock decrypt(const std::string&) = 0;
  virtual SecByteBlock decrypt(const SecByteBlock&) = 0;

  virtual ~Cipher() {}
};

template<typename EncryptMode>
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

  SecByteBlock encrypt(const std::string& input) {
    SecByteBlock bytes = SecByteBlock((byte*) input.data(), input.size());
    return this->encrypt(bytes);
  }
  SecByteBlock encrypt(const SecByteBlock& input) {
    SecByteBlock output(input.size());
    this->encryption.ProcessData(output, input, input.size());
    return output;
  }

  SecByteBlock decrypt(const std::string& input) {
    SecByteBlock bytes = SecByteBlock((byte*) input.data(), input.size());
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
 private:
  static void checkLengthValid(const std::string& method, SecByteBlock& key,
                               SecByteBlock& iv) {
    auto found = cipher_map.find(method);
    if (found == cipher_map.end()) {
      throw InvalidArgument("method name " + method + " is not right");
    }
    if (key.size() != found->second.key_length) {
      throw InvalidArgument("key size is not right, expect " +
          std::to_string(found->second.key_length) +
          ", actual " + std::to_string(key.size()));
    }
    if (iv.size() != found->second.iv_length) {
      throw InvalidArgument("iv size is not right, expect " +
          std::to_string(found->second.iv_length) +
          ", actual " + std::to_string(iv.size()));
    }
  }
 public:
  static std::string HexToString(const SecByteBlock& input) {
    std::string encoded;
    HexEncoder encoder;

    encoder.Put(input, input.size());
    encoder.MessageEnd();
    auto output_size = encoder.MaxRetrievable();
    if (output_size) {
      encoded.resize(output_size);
      encoder.Get((byte*) &encoded[0], encoded.size());
    }

    return encoded;
  }

  static SecByteBlock StringToHex(const std::string& input) {
    SecByteBlock decoded;
    HexDecoder decoder;

    decoder.Put((byte*) input.data(), input.size());
    decoder.MessageEnd();

    auto output_size = decoder.MaxRetrievable();
    if (output_size) {
      decoded.resize(output_size);
      decoder.Get(decoded, decoded.size());
    }
    return decoded;
  }

  // Returns md5 padding password in bytes
  static SecByteBlock PasswordToKey(const std::string& password, size_t key_length) {
    MD5 hash;
    SecByteBlock decoded;
    const int md5_length = 16;

    if (key_length % md5_length != 0) {
      throw InvalidArgument("the length has to be interal times over 16");
    }

    int cnt = (key_length - 1) / md5_length + 1;
    SecByteBlock result(cnt * md5_length);

    auto md5_password =
        Md5Sum(SecByteBlock((byte*) password.data(), password.size()));
    for (int i = 0; i < md5_length; i++) {
      result[i] = md5_password[i];
    }
    SecByteBlock d(md5_length + password.size());
    int start = 0;
    for (int i = 1; i < cnt; i++) {
      start += md5_length;
      for (int j = start - md5_length; j < start; j++) {
        d[j - start + md5_length] = result[j];
      }
      for (int j = 0; j < password.size(); j++) {
        d[md5_length + j] = password[j];
      }
      auto md5_d = Md5Sum(d);
      for (int j = 0; j < md5_length; j++) {
        result[start + j] = md5_d[j];
      }
    }
    result.resize(key_length);
    return result;
  }

  static SecByteBlock Md5Sum(const SecByteBlock& input) {
    MD5 hash;
    std::unique_ptr<byte> decoded;

    hash.Update(input, input.size());
    decoded = std::unique_ptr<byte>(new byte[hash.DigestSize()]);
    hash.Final(decoded.get());

    return SecByteBlock(decoded.get(), hash.DigestSize());
  }

  static std::unique_ptr<Cipher> getEncryption(const std::string& method,
                                               SecByteBlock& key,
                                               SecByteBlock& iv) {
    std::unique_ptr<shadesocks::Cipher> encryption;

    checkLengthValid(method, key, iv);

    if (method.find("cfb") != std::string::npos) {
      encryption = std::unique_ptr<shadesocks::Cipher>(new shadesocks::ShadeCipher<CFB_Mode<AES>>(key, iv));
    } else if (method.find("ctr") != std::string::npos) {
      encryption = std::unique_ptr<shadesocks::Cipher>(new shadesocks::ShadeCipher<CTR_Mode<AES>>(key, iv));
    } else if (method.find("gcm") != std::string::npos) {
      encryption = std::unique_ptr<shadesocks::Cipher>(new shadesocks::ShadeCipher<GCM<AES>>(key, iv));
    } else {
      throw InvalidArgument("cannot encrypt by method: " + method);
    }
    return encryption;
  }

  static std::unique_ptr<Cipher> getEncryption(const std::string& method) {
    LOG(INFO) << "the key is empty, so generate the key";
    int key_length = cipher_map.find(method)->second.key_length;
    int iv_length = cipher_map.find(method)->second.iv_length;
    SecByteBlock key = Util::RandomBlock(key_length);
    SecByteBlock iv = Util::RandomBlock(iv_length);
    return Util::getEncryption(method, key, iv);
  }

  static SecByteBlock RandomBlock(int size) {
    AutoSeededRandomPool rnd;
    SecByteBlock key(0x00, size);  // length is 16
    rnd.GenerateBlock(key, key.size());
    return key;
  }
};

}  // namespace shadesocks
#endif