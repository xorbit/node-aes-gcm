// The MIT License (MIT)
// 
// Copyright (c) 2013 Patrick Van Oosterwijck
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
 
#include <node.h>
#include <nan.h>
#include <openssl/evp.h>

using namespace v8;
using namespace node;


// Authentication tag length

#define AUTH_TAG_LEN  16


// Perform GCM mode AES-128 encryption using the provided key, IV, plaintext
// and auth_data buffers, and return an object containing "ciphertext"
// and "auth_tag" buffers.

void GcmEncrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	Nan::HandleScope scope;

  // We want 4 buffer arguments, key needs to be 16 bytes and IV needs to be
  // 12 bytes
  if (info.Length() < 4 || !Buffer::HasInstance(info[0]) ||
      !Buffer::HasInstance(info[1]) || !Buffer::HasInstance(info[2]) ||
      !Buffer::HasInstance(info[3]) || Buffer::Length(info[0]) != 16 ||
      Buffer::Length(info[1]) != 12) {
    Nan::ThrowError("encrypt requires a 16-byte key Buffer, a 12-byte " \
                      "IV Buffer, a plaintext Buffer and an auth_data " \
                      "Buffer parameter");
    return;
  }

  // Make a buffer for the ciphertext that is the same size as the
  // plaintext, but padded to 16 byte increments
  size_t plaintext_len = Buffer::Length(info[2]);
  size_t ciphertext_len = (((plaintext_len - 1) / 16) + 1) * 16;
  unsigned char *ciphertext = new unsigned char[ciphertext_len];
  // Make a authentication tag buffer
  unsigned char *auth_tag = new unsigned char[AUTH_TAG_LEN];

  // Init OpenSSL interace with 128-bit AES GCM cipher and give it the
  // key and IV
  int outl;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL,
                    (unsigned char *)Buffer::Data(info[0]),
                    (unsigned char *)Buffer::Data(info[1]));
  // Pass additional authenticated data
  // There is some extra complication here because Buffer::Data seems to
  // return NULL for empty buffers, and NULL makes update not work as we
  // expect it to.  So we force a valid non-NULL pointer for empty buffers.
  EVP_EncryptUpdate(ctx, NULL, &outl, Buffer::Length(info[3]) ?
                    (unsigned char *)Buffer::Data(info[3]) : auth_tag,
                    Buffer::Length(info[3]));
  // Encrypt plaintext
  EVP_EncryptUpdate(ctx, ciphertext, &outl,
                    (unsigned char *)Buffer::Data(info[2]),
                    Buffer::Length(info[2]));
  // Finalize
  EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl);
  // Get the authentication tag
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN, auth_tag);
  // Free the OpenSSL interface structure
  EVP_CIPHER_CTX_free(ctx);

  // Create the return buffers and object
  // We strip padding from the ciphertext
  Nan::MaybeLocal<Object> ciphertext_buf = Nan::CopyBuffer((char*)ciphertext,
                                              plaintext_len);
  Nan::MaybeLocal<Object> auth_tag_buf = Nan::CopyBuffer((char*)auth_tag,
                                              AUTH_TAG_LEN);
  Local<Object> return_obj = Nan::New<Object>();
  Nan::Set(return_obj, Nan::New<String>("ciphertext").ToLocalChecked(),
            ciphertext_buf.ToLocalChecked());
  Nan::Set(return_obj, Nan::New<String>("auth_tag").ToLocalChecked(),
            auth_tag_buf.ToLocalChecked());

  // Return it
  info.GetReturnValue().Set(return_obj);
}

// Perform GCM mode AES-128 decryption using the provided key, IV, ciphertext,
// auth_data and auth_tag buffers, and return an object containing a "plaintext"
// buffer and an "auth_ok" boolean.

void GcmDecrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	Nan::HandleScope scope;

  // We want 5 buffer arguments, key needs to be 16 bytes, IV needs to be
  // 12 bytes, auth_tag needs to be 16 bytes
  if (info.Length() < 5 || !Buffer::HasInstance(info[0]) ||
      !Buffer::HasInstance(info[1]) || !Buffer::HasInstance(info[2]) ||
      !Buffer::HasInstance(info[3]) || !Buffer::HasInstance(info[4]) ||
      Buffer::Length(info[0]) != 16 || Buffer::Length(info[1]) != 12 ||
      Buffer::Length(info[4]) != 16) {
    Nan::ThrowError("decrypt requires a 16-byte key Buffer, a 12-byte " \
                      "IV Buffer, a ciphertext Buffer, an auth_data " \
                      "Buffer and a 16-byte auth_tag Buffer parameter");
	return;
  }

  // Make a buffer for the plaintext that is the same size as the
  // ciphertext, but padded to 16 byte increments
  size_t ciphertext_len = Buffer::Length(info[2]);
  size_t plaintext_len = (((ciphertext_len - 1) / 16) + 1) * 16;
  unsigned char *plaintext = new unsigned char[plaintext_len];

  // Init OpenSSL interace with 128-bit AES GCM cipher and give it the
  // key and IV
  int outl;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL,
                    (unsigned char *)Buffer::Data(info[0]),
                    (unsigned char *)Buffer::Data(info[1]));
  // Set the input reference authentication tag
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LEN,
                    Buffer::Data(info[4]));
  // Example showed we needed to do init again
  EVP_DecryptInit_ex(ctx, NULL, NULL,
                    (unsigned char *)Buffer::Data(info[0]),
                    (unsigned char *)Buffer::Data(info[1]));
  // Pass additional authenticated data
  // There is some extra complication here because Buffer::Data seems to
  // return NULL for empty buffers, and NULL makes update not work as we
  // expect it to.  So we force a valid non-NULL pointer for empty buffers.
  EVP_DecryptUpdate(ctx, NULL, &outl, Buffer::Length(info[3]) ?
                    (unsigned char *)Buffer::Data(info[3]) : plaintext,
                    Buffer::Length(info[3]));
  // Decrypt ciphertext
  EVP_DecryptUpdate(ctx, plaintext, &outl,
                    Buffer::Length(info[2]) ?
                    (unsigned char *)Buffer::Data(info[2]) : plaintext,
                    Buffer::Length(info[2]));
  // Finalize
  bool auth_ok = EVP_DecryptFinal_ex(ctx, plaintext + outl, &outl);
  // Free the OpenSSL interface structure
  EVP_CIPHER_CTX_free(ctx);

  // Create the return buffer and object
  // We strip padding from the plaintext
  Nan::MaybeLocal<Object> plaintext_buf = Nan::CopyBuffer((char*)plaintext,
                                             ciphertext_len);
  Local<Object> return_obj = Nan::New<Object>();
  Nan::Set(return_obj, Nan::New<String>("plaintext").ToLocalChecked(),
            plaintext_buf.ToLocalChecked());
  Nan::Set(return_obj, Nan::New<String>("auth_ok").ToLocalChecked(),
            Nan::New<Boolean>(auth_ok));

  // Return it
  info.GetReturnValue().Set(return_obj);
}

// Module init function
void InitAll(Handle<Object> exports) {
  Nan::Set(exports, Nan::New<String>("encrypt").ToLocalChecked(),
            Nan::GetFunction(Nan::New<FunctionTemplate>(GcmEncrypt))
            .ToLocalChecked());
  Nan::Set(exports, Nan::New<String>("decrypt").ToLocalChecked(),
            Nan::GetFunction(Nan::New<FunctionTemplate>(GcmDecrypt))
            .ToLocalChecked());
}

NODE_MODULE(node_aes_gcm, InitAll)

