#include "ss_encrypt.h"
namespace shadesocks {
// params: size the length of the string, which half of the length of bytes
string ShadeEncrypt::HexToString(const byte* input, size_t size) {
  if (size == -1) {
    size = sizeof(input) / 2;
  }
  string encoded;
  HexEncoder encoder;

  encoder.Put(input, size);
  encoder.MessageEnd();
  auto output_size = encoder.MaxRetrievable();
  if (output_size) {
    encoded.resize(output_size);
    encoder.Get((byte*)&encoded[0], encoded.size());
  }

  return encoded;
}
// params: size the length of the string, which half of the length of bytes
SecByteBlock ShadeEncrypt::StringToHex(const string& input, size_t size) {
  if (size < 0) {
    size = input.size();
  }
  SecByteBlock decoded;
  HexDecoder decoder;

  decoder.Put((byte*)input.data(), size);
  decoder.MessageEnd();

  auto output_size = decoder.MaxRetrievable();
  if (output_size) {
    decoded.resize(output_size);
    decoder.Get(decoded, decoded.size());
  }
  return decoded;
}
}  // namespace shadesocks