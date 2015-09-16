Linux:

```


export LIBS+=-ldl
cd zlib-1.2.5
make clean
./configure --prefix=/opt/Source/lib/zlib
make && make install

cd ../openssl-0.9.8r
make clean
./config no-asm --prefix=/opt/Source/lib/openssl --openssldir=/opt/Source/lib/openssl
make && make install

cd ../libssh2-1.3.0
make clean
./configure --with-openssl --with-libssl-prefix=/opt/Source/lib/openssl --with-libz --with-libz-prefix=/opt/Source/lib/zlib --without-libgcrypt --enable-static --prefix=/opt/Source/lib/libssh2
make && make install

cd ../curl-7.23.1
make clean
./configure --with-ssl=/opt/Source/lib/openssl --with-zlib=/opt/Source/lib/zlib --with-libssh2=/opt/Source/lib/libssh2 --disable-rtsp --disable-ldaps --disable-ldap --disable-sspi --without-libidn --enable-static --prefix=/opt/Source/lib/curl
make && make install

```