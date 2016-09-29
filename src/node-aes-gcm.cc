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

#define AUTH_TAG_LEN              16

// Different versions of OpenSSL use different IV length defines

#ifndef EVP_CTRL_GCM_SET_IVLEN
#define EVP_CTRL_GCM_SET_IVLEN    EVP_CTRL_AEAD_SET_IVLEN
#endif


// Perform GCM mode AES-128, AES-192 or AES-256 encryption using the
// provided key, IV, plaintext and auth_data buffers, and return an object
// containing "ciphertext" and "auth_tag" buffers.
// The key length determines the encryption bit level used.

void GcmEncrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	Nan::HandleScope scope;
	const EVP_CIPHER *cipher_type = NULL;
	size_t key_len = 0;

  // The key needs to be 16, 24 or 32 bytes and determines the encryption
  // bit level used
  if (info.Length() >= 1 && Buffer::HasInstance(info[0])) {
    key_len = Buffer::Length(info[0]);
    switch (key_len) {
    case 16:
      cipher_type = EVP_aes_128_gcm();
      break;
    case 24:
      cipher_type = EVP_aes_192_gcm();
      break;
    case 32:
      cipher_type = EVP_aes_256_gcm();
      break;
    default:
      break;
    }
  }

  // We want 4 buffer arguments, key needs to be 16, 24 or 32 bytes
  if (info.Length() < 4 || !cipher_type ||
      !Buffer::HasInstance(info[1]) || !Buffer::HasInstance(info[2]) ||
      !Buffer::HasInstance(info[3])) {
    Nan::ThrowError("encrypt requires a 16, 24 or 32-byte key Buffer, " \
                      "an IV Buffer, a plaintext Buffer and an " \
                      "auth_data Buffer parameter");
    return;
  }

  // Make a buffer for the ciphertext that is the same size as the
  // plaintext, but padded to key size increments
  int plaintext_len = (int)Buffer::Length(info[2]);
  int ciphertext_len = (((plaintext_len - 1) / key_len) + 1) * key_len;
  unsigned char *ciphertext = new unsigned char[ciphertext_len];
  // Make a authentication tag buffer
  unsigned char *auth_tag = new unsigned char[AUTH_TAG_LEN];

  // Create the OpenSSL context
  int outl;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // Init the OpenSSL interface with the selected AES GCM cipher
  EVP_EncryptInit_ex(ctx, cipher_type, NULL, NULL, NULL);
  // Set the IV length
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                    Buffer::Length(info[1]), NULL);
  // Init OpenSSL interace with the key and IV
  EVP_EncryptInit_ex(ctx, NULL, NULL,
                    (unsigned char *)Buffer::Data(info[0]),
                    (unsigned char *)Buffer::Data(info[1]));
  // Pass additional authenticated data
  // There is some extra complication here because Buffer::Data seems to
  // return NULL for empty buffers, and NULL makes update not work as we
  // expect it to.  So we force a valid non-NULL pointer for empty buffers.
  EVP_EncryptUpdate(ctx, NULL, &outl, Buffer::Length(info[3]) ?
                    (unsigned char *)Buffer::Data(info[3]) : auth_tag,
                    (int)Buffer::Length(info[3]));
  // Encrypt plaintext
  EVP_EncryptUpdate(ctx, ciphertext, &outl,
                    (unsigned char *)Buffer::Data(info[2]),
                    (int)Buffer::Length(info[2]));
  // Finalize
  EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl);
  // Get the authentication tag
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN, auth_tag);
  // Free the OpenSSL interface structure
  EVP_CIPHER_CTX_free(ctx);

  // Create the return buffers and object
  // We strip padding from the ciphertext
  Nan::MaybeLocal<Object> ciphertext_buf = Nan::CopyBuffer((char*)ciphertext,
                                              (uint32_t)plaintext_len);
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

// Perform GCM mode AES-128, AES-192 or AES-256 decryption using the
// provided key, IV, ciphertext, auth_data and auth_tag buffers, and return
// an object containing a "plaintext" buffer and an "auth_ok" boolean.
// The key length determines the encryption bit level used.

void GcmDecrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	Nan::HandleScope scope;
	const EVP_CIPHER *cipher_type = NULL;
	size_t key_len = 0;

  // The key needs to be 16, 24 or 32 bytes and determines the encryption
  // bit level used
  if (info.Length() >= 1 && Buffer::HasInstance(info[0])) {
    key_len = Buffer::Length(info[0]);
    switch (key_len) {
    case 16:
      cipher_type = EVP_aes_128_gcm();
      break;
    case 24:
      cipher_type = EVP_aes_192_gcm();
      break;
    case 32:
      cipher_type = EVP_aes_256_gcm();
      break;
    default:
      break;
    }
  }

  // We want 5 buffer arguments, key needs to be 16, 24 or 32 bytes,
  // auth_tag needs to be 16 bytes
  if (info.Length() < 5 || !cipher_type ||
      !Buffer::HasInstance(info[1]) || !Buffer::HasInstance(info[2]) ||
      !Buffer::HasInstance(info[3]) || !Buffer::HasInstance(info[4]) ||
      Buffer::Length(info[4]) != 16) {
    Nan::ThrowError("decrypt requires a 16, 24 or 32-byte key Buffer, " \
                      "an IV Buffer, a ciphertext Buffer, an auth_data " \
                      "Buffer and a 16-byte auth_tag Buffer parameter");
	return;
  }

  // Make a buffer for the plaintext that is the same size as the
  // ciphertext, but padded to key size increments
  int ciphertext_len = (int)Buffer::Length(info[2]);
  int plaintext_len = (((ciphertext_len - 1) / key_len) + 1) * key_len;
  unsigned char *plaintext = new unsigned char[plaintext_len];

  // Create the OpenSSL context
  int outl;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // Init the OpenSSL interface with the selected AES GCM cipher
  EVP_DecryptInit_ex(ctx, cipher_type, NULL, NULL, NULL);
  // Set the IV length
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                    Buffer::Length(info[1]), NULL);
  // Init OpenSSL interace with the key and IV
  EVP_DecryptInit_ex(ctx, NULL, NULL,
                    (unsigned char *)Buffer::Data(info[0]),
                    (unsigned char *)Buffer::Data(info[1]));
  // Pass additional authenticated data
  // There is some extra complication here because Buffer::Data seems to
  // return NULL for empty buffers, and NULL makes update not work as we
  // expect it to.  So we force a valid non-NULL pointer for empty buffers.
  EVP_DecryptUpdate(ctx, NULL, &outl, Buffer::Length(info[3]) ?
                    (unsigned char *)Buffer::Data(info[3]) : plaintext,
                    (int)Buffer::Length(info[3]));
  // Decrypt ciphertext
  EVP_DecryptUpdate(ctx, plaintext, &outl,
                    Buffer::Length(info[2]) ?
                    (unsigned char *)Buffer::Data(info[2]) : plaintext,
                    (int)Buffer::Length(info[2]));
  // Set the input reference authentication tag
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LEN,
                    Buffer::Data(info[4]));
  // Finalize
  bool auth_ok = EVP_DecryptFinal_ex(ctx, plaintext + outl, &outl);
  // Free the OpenSSL interface structure
  EVP_CIPHER_CTX_free(ctx);

  // Create the return buffer and object
  // We strip padding from the plaintext
  Nan::MaybeLocal<Object> plaintext_buf = Nan::CopyBuffer((char*)plaintext,
                                             (uint32_t)ciphertext_len);
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

