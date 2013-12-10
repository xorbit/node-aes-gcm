// Test module for node-aes-gcm
// Verifies against applicable test cases documented in:
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents
// /proposedmodes/gcm/gcm-revised-spec.pdf

require('buffertools');
var fs = require('fs');
var should = require('should');
var gcm = require('../build/Release/node_aes_gcm');


describe('node-aes-gcm', function () {
  var key, iv, plaintext, aad, ciphertext, auth_tag;
  var encrypted, decrypted, decryptedBadCiphertext,
      decryptedBadAad, decryptedBadAuthTag;
  var badCiphertext = new Buffer('Bad ciphertext'),
      badAad = new Buffer('Bad AAD'),
      badAuthTag = new Buffer('0000000000000000');

  function runEncryptDecryptTestCases(nist) {
    before(function () {
      encrypted = gcm.encrypt(key, iv, plaintext, aad);
      if (encrypted && encrypted.ciphertext && encrypted.auth_tag) {
        decrypted = gcm.decrypt(key, iv, encrypted.ciphertext,
                                aad, encrypted.auth_tag);
        decryptedBadCiphertext = gcm.decrypt(key, iv, badCiphertext,
                                aad, encrypted.auth_tag);
        decryptedBadAad = gcm.decrypt(key, iv, encrypted.ciphertext,
                                badAad, encrypted.auth_tag);
        decryptedBadAuthTag = gcm.decrypt(key, iv, encrypted.ciphertext,
                                aad, badAuthTag);
      } else {
        decrypted = null;
      }
    });

    if (nist) {
      it('should match the NIST ciphertext when encrypted', function () {
        encrypted.should.have.ownProperty('ciphertext');
        encrypted.ciphertext.should.be.a.Buffer;
        encrypted.ciphertext.equals(ciphertext).should.be.ok;
      });

      it('should match the NIST authentication tag when encrypted',
          function () {
        encrypted.should.have.ownProperty('auth_tag');
        encrypted.auth_tag.should.be.a.Buffer;
        encrypted.auth_tag.equals(auth_tag).should.be.ok;
      });
    }

    it('should decrypt back to the original plaintext', function () {
      decrypted.should.have.ownProperty('plaintext');
      decrypted.plaintext.should.be.a.Buffer;
      decrypted.plaintext.equals(plaintext).should.be.ok;
    });

    it('should report authentication ok when decrypted', function () {
      decrypted.should.have.ownProperty('auth_ok');
      decrypted.auth_ok.should.be.a.Boolean;
      decrypted.auth_ok.should.be.ok;
    });

    it('should fail authentication when decrypting bad ciphertext',
        function () {
      decryptedBadCiphertext.should.have.ownProperty('auth_ok');
      decryptedBadCiphertext.auth_ok.should.be.a.Boolean;
      decryptedBadCiphertext.auth_ok.should.not.be.ok;
    });

    it('should decrypt correctly even with bad AAD', function () {
      decryptedBadAad.should.have.ownProperty('plaintext');
      decryptedBadAad.plaintext.should.be.a.Buffer;
      decryptedBadAad.plaintext.equals(plaintext).should.be.ok;
    });

    it('should fail authentication when decrypting bad AAD',
        function () {
      decryptedBadAad.should.have.ownProperty('auth_ok');
      decryptedBadAad.auth_ok.should.be.a.Boolean;
      decryptedBadAad.auth_ok.should.not.be.ok;
    });

    it('should decrypt correctly even with bad authentication tag',
        function () {
      decryptedBadAuthTag.should.have.ownProperty('plaintext');
      decryptedBadAuthTag.plaintext.should.be.a.Buffer;
      decryptedBadAuthTag.plaintext.equals(plaintext).should.be.ok;
    });

    it('should fail authentication with a bad authentication tag',
        function () {
      decryptedBadAuthTag.should.have.ownProperty('auth_ok');
      decryptedBadAuthTag.auth_ok.should.be.a.Boolean;
      decryptedBadAuthTag.auth_ok.should.not.be.ok;
    });
  }

  describe('NIST Test Case 1', function () {
    before(function () {
      key = new Buffer('00000000000000000000000000000000', 'hex');
      iv = new Buffer('000000000000000000000000', 'hex');
      plaintext = new Buffer([]);
      aad = new Buffer([]);
      ciphertext = new Buffer([]);
      auth_tag = new Buffer('58e2fccefa7e3061367f1d57a4e7455a', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('NIST Test Case 2', function () {
    before(function () {
      key = new Buffer('00000000000000000000000000000000', 'hex');
      iv = new Buffer('000000000000000000000000', 'hex');
      plaintext = new Buffer('00000000000000000000000000000000', 'hex');
      aad = new Buffer([]);
      ciphertext = new Buffer('0388dace60b6a392f328c2b971b2fe78', 'hex');
      auth_tag = new Buffer('ab6e47d42cec13bdf53a67b21257bddf', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('NIST Test Case 3', function () {
    before(function () {
      key = new Buffer('feffe9928665731c6d6a8f9467308308', 'hex');
      iv = new Buffer('cafebabefacedbaddecaf888', 'hex');
      plaintext = new Buffer('d9313225f88406e5a55909c5aff5269a' +
                             '86a7a9531534f7da2e4c303d8a318a72' +
                             '1c3c0c95956809532fcf0e2449a6b525' +
                             'b16aedf5aa0de657ba637b391aafd255', 'hex');
      aad = new Buffer([]);
      ciphertext = new Buffer('42831ec2217774244b7221b784d0d49c' +
                              'e3aa212f2c02a4e035c17e2329aca12e' +
                              '21d514b25466931c7d8f6a5aac84aa05' +
                              '1ba30b396a0aac973d58e091473f5985', 'hex');
      auth_tag = new Buffer('4d5c2af327cd64a62cf35abd2ba6fab4', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('NIST Test Case 4', function () {
    before(function () {
      key = new Buffer('feffe9928665731c6d6a8f9467308308', 'hex');
      iv = new Buffer('cafebabefacedbaddecaf888', 'hex');
      plaintext = new Buffer('d9313225f88406e5a55909c5aff5269a' +
                             '86a7a9531534f7da2e4c303d8a318a72' +
                             '1c3c0c95956809532fcf0e2449a6b525' +
                             'b16aedf5aa0de657ba637b39', 'hex');
      aad = new Buffer('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex');
      ciphertext = new Buffer('42831ec2217774244b7221b784d0d49c' +
                              'e3aa212f2c02a4e035c17e2329aca12e' +
                              '21d514b25466931c7d8f6a5aac84aa05' +
                              '1ba30b396a0aac973d58e091', 'hex');
      auth_tag = new Buffer('5bc94fbc3221a5db94fae95ae7121a47', 'hex');
    });

    runEncryptDecryptTestCases(true);
  });

  describe('Its own binary module', function () {
    before(function (done) {
      key = new Buffer('8888888888888888');
      iv = new Buffer('666666666666');
      fs.readFile('./build/Release/node_aes_gcm.node', function (err, data) {
        if (err) throw err;
        plaintext = data;
        done();
      });
      aad = new Buffer([]);
      ciphertext = null;
      auth_tag = null;
    });

    runEncryptDecryptTestCases(false);
  });
});
