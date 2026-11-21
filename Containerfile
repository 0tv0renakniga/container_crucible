FROM registry.access.redhat.com/ubi8/ubi:latest
WORKDIR /app

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
ENV MPLBACKEND=Agg
ENV VIRTUAL_ENV=/opt/venv
ENV PATH=/opt/venv/bin:/usr/local/bin:$PATH
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages:/usr/local/lib64/python3.11/site-packages:/app/repo/Python:/app/repo/Python/ctypesgen
COPY autoprobe-env.sh /etc/profile.d/autoprobe.sh
RUN ["/bin/bash", "-lc", "sed -i '/^\\[ubi-8-codeready-builder\\]/,/^\\[/ s/^enabled *= *0/enabled = 1/' /etc/yum.repos.d/ubi.repo || true"]
RUN ["/bin/bash", "-lc", "dnf install -y make gcc gcc-c++ autoconf automake libtool diffutils file tar gzip patch git which pkgconf-pkg-config && dnf clean all"]
RUN ["/bin/bash", "-lc", "set -eux; rm -rf /opt/venv; dnf install -y python3.11 python3.11-devel python3.11-pip && dnf clean all && python3.11 -m venv /opt/venv && /opt/venv/bin/pip install -U pip setuptools wheel"]
RUN ["/bin/bash", "-lc", "pip install python-dateutil && pip install matplotlib && pip install numpy && pip install scipy && pip install spacepy"]
RUN ["/bin/bash", "-lc", "set -eux; cd /tmp; curl -fL --retry 3 https://ftp.gnu.org/gnu/gsl/gsl-2.8.tar.gz -o gsl.tgz; tar xzf gsl.tgz; cd gsl-2.8; ./configure --prefix=/usr/local; make -j\"$(nproc)\"; make install; echo /usr/local/lib > /etc/ld.so.conf.d/usr-local.conf; ldconfig; cd /; rm -rf /tmp/gsl*"]
RUN ["/bin/bash", "-lc", "set -eux; (dnf install -y zlib-devel || true); cd /tmp; curl -fL --retry 3 https://github.com/HDFGroup/hdf5/releases/download/hdf5_1.14.4.3/hdf5-1.14.4-3.tar.gz -o hdf5.tgz; tar xzf hdf5.tgz; cd hdf5-1.14.4-3; ./configure --prefix=/usr/local --enable-build-mode=production --enable-hl; make -j\"$(nproc)\"; make install; echo /usr/local/lib > /etc/ld.so.conf.d/usr-local.conf; ldconfig; test -f /usr/local/include/hdf5.h; cd /; rm -rf /tmp/hdf5*"]

COPY LANLGeoMag /app/repo
RUN ["/bin/bash", "-lc", "set -eo pipefail\nmake --version\ng++ --version\nautoreconf --version\ncd /app/repo && autoreconf -i && ./configure && make\ncd /app/repo && make install && ldconfig"]
CMD ["/bin/bash", "-l"]
