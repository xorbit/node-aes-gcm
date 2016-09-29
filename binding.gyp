{
  "targets": [
    {
      "target_name": "node_aes_gcm",
      "sources": [
        "src/node-aes-gcm.cc"
      ],
      'conditions': [
        [ 'OS=="win"', {
          'conditions': [
            # "openssl_root" is the directory on Windows of the OpenSSL files
            ['target_arch=="x64"', {
              'variables': {
                'openssl_root%': 'C:/OpenSSL-Win64'
              },
	      'libraries': ['<(openssl_root)/lib/<!@(dir /B C:\OpenSSL-Win64\lib\libeay32.lib C:\OpenSSL-Win64\lib\libcrypto.lib)'],
            }, {
              'variables': {
                'openssl_root%': 'C:/OpenSSL-Win32'
              },
	      'libraries': ['<(openssl_root)/lib/<!@(dir /B C:\OpenSSL-Win32\lib\libeay32.lib C:\OpenSSL-Win32\lib\libcrypto.lib)'],
            }],
          ],
          'defines': [
            'uint=unsigned int',
          ],
          'include_dirs': [
            '<(openssl_root)/include',
            '<!(node -e "require(\'nan\')")',
          ],
        }, { # OS!="win"
          'include_dirs': [
            # use node's bundled openssl headers on Unix platforms
            '<(node_root_dir)/deps/openssl/openssl/include',
            '<!(node -e "require(\'nan\')")',
          ],
        }],
      ],
    }
  ]
}
