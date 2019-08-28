#include "ss_encrypt.h"

namespace shadesocks {
// params: size the length of the bytes
string ShadeEncrypt::HexToString(const SecByteBlock& input) {
  string encoded;
  HexEncoder encoder;

  encoder.Put(input, input.size());
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

SecByteBlock ShadeEncrypt::Md5Sum(const SecByteBlock& input) {
  MD5 hash;
  byte* decoded;

  hash.Update(input, input.size());
  decoded = new byte[hash.DigestSize()];
  hash.Final(decoded);

  return SecByteBlock(decoded, hash.DigestSize());
}

SecByteBlock ShadeEncrypt::PasswordToKey(const string& password,
                                         size_t key_length) {
  MD5 hash;
  SecByteBlock decoded;
  const int md5_length = 16;

  if(key_length % md5_length !=0){
    throw InvalidArgument("the length has to be interal times over 16");
  }

  int cnt = (key_length - 1) / md5_length + 1;
  SecByteBlock result(cnt * md5_length);

  auto md5_password =
      Md5Sum(SecByteBlock((byte*)password.data(), password.size()));
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
}  // namespace shadesocks