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

#include <modes.h>
using CryptoPP::CFB_Mode;

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
class ShadeEncrypt {
 public:
  static string HexToString(const SecByteBlock&);
  static SecByteBlock StringToHex(const string& input);
  // Returns md5 padding password in bytes
  static SecByteBlock PasswordToKey(const string& password, size_t key_length);
  static SecByteBlock Md5Sum(const SecByteBlock&);

  virtual SecByteBlock encrypt(const SecByteBlock&) = 0;
  virtual SecByteBlock decrypt(const SecByteBlock&) = 0;
};

class ShadeEncryptCFB : ShadeEncrypt {
 private:
  CFB_Mode<AES>::Encryption encryption;
  CFB_Mode<AES>::Decryption decryption;

 public:
  ShadeEncryptCFB(SecByteBlock key, SecByteBlock iv)
      : encryption(key, key.size(), iv), decryption(key, key.size(), iv) {}
  SecByteBlock encrypt(const string&);
  SecByteBlock encrypt(const SecByteBlock&);
  
  SecByteBlock decrypt(const string&);
  SecByteBlock decrypt(const SecByteBlock&);
};
}  // namespace shadesocks
#endif