#!/bin/bash
PROJECT_DIR=$(cd ../..; pwd)
DEBBUILD_DIR=$(mktemp -u /tmp/debbuild.XXXX)
SCRIPT_DIR=$(pwd)
PACKAGE=rats-tls
VERSION=$(cd ../..; cat ./VERSION)
RELEASE_TARBALL=$DEBBUILD_DIR/v$VERSION.tar.gz
TARBALL_NAME=$PACKAGE\_$VERSION.orig.tar.gz
DEB_BUILD_FOLDER=$DEBBUILD_DIR/$PACKAGE-$VERSION

# create and rename the tarball
mkdir -p $DEBBUILD_DIR
if [ ! -f "$RELEASE_TARBALL" ]; then
        cp -r $PROJECT_DIR $DEB_BUILD_FOLDER
fi
cd $DEBBUILD_DIR && tar zcfP $TARBALL_NAME $PACKAGE-$VERSION

if [ -z "$SGX_SDK" ]; then
        SGX_SDK="/opt/intel/sgxsdk"
fi

# If the SGX SDK is not prepared well in build environment, stop the build
if [ ! -d "$SGX_SDK" ]; then
        echo 'Error: The SGX_SDK environment variable value is not correct'
        exit 1
fi

# Use multiple modes
BUILD_MODE[0]=host
BUILD_MODE[1]=tdx
BUILD_MODE[2]=occlum
BUILD_MODE[3]=sgx

# Generate deb packages by looping through multiple modes
for BUILD_MODE in "${BUILD_MODE[@]}"; do
        echo "Start build deb package with mode $BUILD_MODE"
        rm -rf $DEB_BUILD_FOLDER/src
        cp -r $PROJECT_DIR/src $DEB_BUILD_FOLDER/src
        cp -rf  $SCRIPT_DIR/debian $DEB_BUILD_FOLDER
        cd $DEB_BUILD_FOLDER
	sed 's/Package: rats-tls/Package: rats-tls-'$BUILD_MODE'/g' debian/control.in > debian/control 
        sed 's/cmake -DBUILD_SAMPLES=on -H. -Bbuild/cmake -DRATS_TLS_BUILD_MODE="'$BUILD_MODE'" -DBUILD_SAMPLES=on -H. -Bbuild/g' debian/rules.in > debian/rules
        sed -i 's/rats-tls-host/rats-tls-'$BUILD_MODE'/g' debian/rules
        if [ $BUILD_MODE == "sgx" ]; then
                sed -i '/dh_strip --exclude=rats-tls-server/c\\tdh_strip --exclude=rats-tls-server --exclude=rats-tls-client --exclude=sgx_stub_enclave.signed.so --exclude=librats_tls.a --exclude=librats_tls_u.a --exclude=librtls_edl_t.a --exclude=libtls_wrapper*.a --exclude=libcrypto_wrapper*.a --exclude=libattester*.a --exclude=libverifier*.a' debian/rules
                dpkg-buildpackage -us -uc
        else
                DEB_CFLAGS_SET="-std=gnu11 -fPIC" DEB_CXXFLAGS_SET="-std=c++11 -fPIC" DEB_LDFLAGS_SET="-fPIC" dpkg-buildpackage -us -uc
        fi
        cp $DEBBUILD_DIR/*.*.deb $PROJECT_DIR
        rm -rf $DEB_BUILD_FOLDER/build
        rm -rf $DEB_BUILD_FOLDER/debian
        echo "Successfully build deb package with mode $BUILD_MODE"
done

rm -rf $DEBBUILD_DIR
