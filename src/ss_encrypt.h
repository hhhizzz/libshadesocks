#ifndef SS_ENCRYPT_H__
#define SS_ENCRYPT_H__

#include <stdexcept>
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

namespace shadesocks {
class ShadeEncrypt {
 private:
 public:
  static string HexToString(const byte* input, size_t size);
  static SecByteBlock StringToHex(const string& input, size_t size);
};
}  // namespace shadesocks
#endif