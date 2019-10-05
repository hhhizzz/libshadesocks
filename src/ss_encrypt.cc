#include "ss_encrypt.h"

namespace shadesocks {
string Util::HexToString(const SecByteBlock& input) {
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

SecByteBlock Util::StringToHex(const string& input) {
  SecByteBlock decoded;
  HexDecoder decoder;

  decoder.Put((byte*)input.data(), input.size());
  decoder.MessageEnd();

  auto output_size = decoder.MaxRetrievable();
  if (output_size) {
    decoded.resize(output_size);
    decoder.Get(decoded, decoded.size());
  }
  return decoded;
}

SecByteBlock Util::Md5Sum(const SecByteBlock& input) {
  MD5 hash;
  byte* decoded;

  hash.Update(input, input.size());
  decoded = new byte[hash.DigestSize()];
  hash.Final(decoded);

  return SecByteBlock(decoded, hash.DigestSize());
}

SecByteBlock Util::PasswordToKey(const string& password, size_t key_length) {
  MD5 hash;
  SecByteBlock decoded;
  const int md5_length = 16;

  if (key_length % md5_length != 0) {
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

void checkLengthValid(const string& method, SecByteBlock& key,
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

std::unique_ptr<Cipher> Util::getEncryption(const string& method) {
  LOG(INFO) << "the key is empty, so generate the key";
  int key_length = cipher_map.find(method)->second.key_length;
  int iv_length = cipher_map.find(method)->second.iv_length;
  SecByteBlock key = Util::RandomBlock(key_length);
  SecByteBlock iv = Util::RandomBlock(iv_length);
  return Util::getEncryption(method, key, iv);
}

std::unique_ptr<Cipher> Util::getEncryption(const string& method,
                                            SecByteBlock& key,
                                            SecByteBlock& iv) {
  std::unique_ptr<shadesocks::Cipher> encryption;

  checkLengthValid(method, key, iv);

  if (method.find("cfb") != std::string::npos) {
    encryption.reset(new shadesocks::ShadeCipher<CFB_Mode<AES>>(key, iv));
  } else if (method.find("ctr") != std::string::npos) {
    encryption.reset(new shadesocks::ShadeCipher<CTR_Mode<AES>>(key, iv));
  } else if (method.find("gcm") != std::string::npos) {
    encryption.reset(new shadesocks::ShadeCipher<GCM<AES>>(key, iv));
  } else {
    throw InvalidArgument("cannot encrypt by method: " + method);
  }
  return encryption;
}

SecByteBlock Util::RandomBlock(int size) {
  AutoSeededRandomPool rnd;
  SecByteBlock key(0x00, size);  // length is 16
  rnd.GenerateBlock(key, key.size());
  return key;
}

}  // namespace shadesocks