#include "ss_encrypt.h"
namespace shadesocks {
string ShadeEncrypt::HexToString(const byte* input, size_t size) {
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
SecByteBlock ShadeEncrypt::StringToHex(const string& input, size_t size) {
  SecByteBlock decoded;
  HexDecoder decoder;

  decoder.Put(decoded, size);
  decoder.MessageEnd();

  auto output_size = decoder.MaxRetrievable();
  if(output_size){
    decoded.resize(output_size);
    decoder.Get(decoded,decoded.size());
  }
  return decoded;
}
}  // namespace shadesocks