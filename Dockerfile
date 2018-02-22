FROM alpine:3.6

RUN apk add --no-cache \
      autoconf \
      automake \
      build-base \
      bzip2-dev \
      cmake \
      expat-dev \
      gettext-dev \
      gperf \
      libjpeg-turbo-dev \
      libpng-dev \
      libtool \
      linux-headers \
      py-lxml \
      py-six \
      python3 \
      python \
      zlib-dev

COPY ./vendor /src/vendor
WORKDIR /src
RUN chown nobody:nogroup -R /src

USER nobody:nogroup

RUN cd vendor/git.savannah.gnu.org/r/freetype/freetype2.git/ \
 && NOCONFIGURE=1 ./autogen.sh \
 # workaround for docker #9547 (Text file busy) \
 && sync \
 && mkdir build && cd build \
 && ../configure --prefix=$PWD/install --enable-static \
 && make -j5 \
 && make install

ENV PKG_CONFIG_PATH="/src/vendor/git.savannah.gnu.org/r/freetype/freetype2.git/build/install/lib/pkgconfig:$PKG_CONFIG_PATH"
ENV LINKFLAGS="-L/src/vendor/git.savannah.gnu.org/r/freetype/freetype2.git/build/install/lib $LINKFLAGS"
# Required for poppler cmake
ENV FREETYPE_DIR=/src/vendor/git.savannah.gnu.org/r/freetype/freetype2.git/build/install


RUN cd vendor/anongit.freedesktop.org/git/fontconfig \
 && NOCONFIGURE=1 ./autogen.sh \
 && mkdir build && cd build \
 && ../configure --prefix=$PWD/install --enable-static \
 && make -j5 \
 && make install

ENV PKG_CONFIG_PATH="/src/vendor/anongit.freedesktop.org/git/fontconfig/build/install/lib/pkgconfig:$PKG_CONFIG_PATH"
ENV LINKFLAGS="-L/src/vendor/anongit.freedesktop.org/git/fontconfig/build/install/lib $LINKFLAGS"


RUN cd vendor/github.com/mm2/Little-CMS/ \
 && mkdir build && cd build \
 && ../configure --prefix=$PWD/install --enable-static \
 && make -j5 \
 && make install

ENV PKG_CONFIG_PATH="/src/vendor/github.com/mm2/Little-CMS/build/install/lib/pkgconfig:$PKG_CONFIG_PATH"
ENV LINKFLAGS="-L/src/vendor/github.com/mm2/Little-CMS/build/install/lib $LINKFLAGS"


RUN cd vendor/github.com/uclouvain/openjpeg/ \
 && mkdir build && cd build \
 && cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$PWD/install \
 && make -j5 \
 && make install

ENV PKG_CONFIG_PATH="/src/vendor/github.com/uclouvain/openjpeg/build/install/lib/pkgconfig:$PKG_CONFIG_PATH"
ENV CXXFLAGS="-I/src/vendor/github.com/uclouvain/openjpeg/build/install/include $CXXFLAGS"
ENV LDFLAGS="-L/src/vendor/github.com/uclouvain/openjpeg/build/install/lib $LDFLAGS"
ENV LINKFLAGS="-L/src/vendor/github.com/uclouvain/openjpeg/build/install/lib $LINKFLAGS"


RUN cd vendor/anongit.freedesktop.org/git/poppler/poppler.git \
 && mkdir build && cd build \
 && cmake .. \
          -DCMAKE_INSTALL_PREFIX=$PWD/install \
          -DENABLE_GLIB:BOOL=OFF \
          -DENABLE_CPP:BOOL=OFF \
          -DENABLE_UTILS:BOOL=OFF \
          -DBUILD_SHARED_LIBS:BOOL=OFF \
          -DBUILD_GTK_TESTS:BOOL=OFF \
          -DBUILD_QT4_TESTS:BOOL=OFF \
          -DBUILD_QT5_TESTS:BOOL=OFF \
          -DBUILD_CPP_TESTS:BOOL=OFF \
          -DENABLE_XPDF_HEADERS:BOOL=ON \
          -DCMAKE_BUILD_TYPE:STRING=release \
          -DENABLE_LIBOPENJPEG:STRING=openjpeg2 \
 && make V=1 -j4 \
 && make install

ENV PKG_CONFIG_PATH="/src/vendor/anongit.freedesktop.org/git/poppler/poppler.git/build/install/lib64/pkgconfig:$PKG_CONFIG_PATH"
ENV LINKFLAGS="-L/src/vendor/anongit.freedesktop.org/git/poppler/poppler.git/build/install/lib64 $LINKFLAGS"
ENV CXXFLAGS="-I/src/vendor/anongit.freedesktop.org/git/poppler/poppler.git/build/install/include $CXXFLAGS"


COPY ./src /src/src
COPY waf waf
COPY msgpack-c msgpack-c
COPY wscript wscript


RUN ./waf configure --static --release
RUN ./waf build


ENTRYPOINT ["/src/build/pdf2msgpack"]
