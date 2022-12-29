%global nspr_version 4.35.0
%global nss_version 3.85.0
%global nss_archive_version 3.85
%global unsupported_tools_directory %{_libdir}/nss/unsupported-tools
%global allTools "certutil cmsutil crlutil derdump modutil pk12util signtool signver ssltap vfychain vfyserv"

%global dracutlibdir %{_prefix}/lib/dracut
%global dracut_modules_dir %{dracutlibdir}/modules.d/05nss-softokn/
%global dracut_conf_dir %{dracutlibdir}/dracut.conf.d

%bcond_with test
%bcond_without dbm

Summary:          Network Security Services
Name:             nss
Version:          %{nss_version}
Release:          1
License:          MPLv2.0
URL:              http://www.mozilla.org/projects/security/pki/nss/
Provides:         nss-system-init
Requires:         nspr >= %{nspr_version} nss-util >= %{nss_version} nss-softokn%{_isa} >= %{nss_version}
Requires:         p11-kit-trust crypto-policies 
Requires(post):   coreutils, sed
BuildRequires:    nspr-devel >= %{nspr_version} nss-softokn sqlite-devel zlib-devel
BuildRequires:    pkgconf gawk psmisc perl-interpreter gcc-c++ 
obsoletes:	  nss-sysinit < %{version}-%{release}

Source0:          https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_85_RTM/src/%{name}-%{nss_archive_version}.tar.gz
Source1:          nss-util.pc
Source2:          nss-util-config
Source3:          nss-softokn.pc
Source4:          nss-softokn-config
Source8:          nss.pc
Source9:          nss-config
Source10:         blank-cert8.db
Source11:         blank-key3.db
Source12:         blank-secmod.db
Source13:         blank-cert9.db
Source14:         blank-key4.db
Source15:         system-pkcs11.txt
Source16:         setup-nsssysinit.sh

# Feature: support sm2 and sm3
Patch9000:        Feature-nss-add-implement-of-SM3-digest-algorithm.patch
Patch9001:        Feature-nss-add-implement-of-SM2-signature-algorithm.patch  
Patch9002:        Feature-nss-support-SM3-digest-algorithm.patch
Patch9003:        Feature-nss-support-SM2-signature-algorithm.patch

%description
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

%package devel
Summary:          Network Security Services development files
Provides:         nss-static = %{version}-%{release}
Provides:         nss-pkcs11-devel-static = %{version}-%{release}
Provides:         nss-pkcs11-devel
Requires:         nss%{?_isa} = %{version}-%{release}
Requires:         nss-util-devel nss-softokn-devel nspr-devel >= %{nspr_version} pkgconf
Requires:         nss-softokn-devel = %{version}-%{release}
BuildRequires:    xmlto
Obsoletes:        nss-pkcs11-devel < %{version}-%{release}

%description devel
Header and Library files for doing development with Network Security Services.

%package util
Summary:          Network Security Services Utilities Library
Requires:         nspr >= %{nspr_version} 
Requires:         %{name}%{?_isa} = %{version}-%{release}
Provides:         nss-tools = %{version}-%{release}
Obsoletes:        nss-tools < %{version}-%{release}

%description util
Utilities for Network Security Services and the Softoken module
manipulate the NSS certificate and key database.

%package util-devel
Summary:          Development libraries for Network Security Services Utilities
Requires:         nss-util%{?_isa} = %{version}-%{release}
Requires:         nspr-devel >= %{nspr_version}
Requires:         pkgconf

%description util-devel
Header and library files for doing development with Network Security Services.

%package softokn
Summary:          Network Security Services Softoken and Freebl library Module
Requires:         nspr >= %{nspr_version}
Requires:         nss-util >= %{version}-%{release}
Provides:         nss-softokn-freebl
Conflicts:        prelink < 0.4.3
Conflicts:        filesystem < 3
Obsoletes:	  nss-softokn-freebl < %{version}-%{release}

%description softokn
Network Security Services Softoken and Freebl Cryptographic Module

%package softokn-devel
Summary:          Header and Library files for doing development with the Freebl library for NSS
Provides:         nss-softokn-freebl-static = %{version}-%{release}
Provides:         nss-softokn-freebl-devel
Requires:         nss-softokn%{?_isa} = %{version}-%{release}
Requires:         nspr-devel >= %{nspr_version}
Requires:         nss-util-devel >= %{version}-%{release}
Requires:         pkgconf
BuildRequires:    nspr-devel >= %{nspr_version}
Obsoletes:	  nss-softokn-freebl-devel < %{version}-%{release}

%description softokn-devel
NSS Softoken Cryptographic Module and Freebl Library Development Tools
This package supports special needs of some PKCS #11 module developers and
is otherwise considered private to NSS. As such, the programming interfaces
may change and the usual NSS binary compatibility commitments do not apply.
Developers should rely only on the officially supported NSS public API.

%package help
Summary:          help document for NSS
Requires:         man-db

%description help
Help document for NSS

%prep
%setup -q -n %{name}-%{nss_archive_version}

pushd nss
%patch9000 -p1
%patch9001 -p1
%patch9002 -p1
%patch9003 -p1
popd

%build

export NSS_FORCE_FIPS=1
# Enable compiler optimizations and disable debugging code

export BUILD_OPT=1
# Uncomment to disable optimizations
#RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | sed -e 's/-O2/-O0/g'`
#export RPM_OPT_FLAGS

# Generate symbolic info for debuggers
export XCFLAGS=$RPM_OPT_FLAGS
export LDFLAGS=$RPM_LD_FLAGS
export DSO_LDOPTS=$RPM_LD_FLAGS

# Must export FREEBL_LOWHASH=1 for nsslowhash.h so that it gets
# copied to dist and the rpm install phase can find it
# This due of the upstream changes to fix
# https://bugzilla.mozilla.org/show_bug.cgi?id=717906
export FREEBL_LOWHASH=1
# uncomment if the iquote patch is activated
export IN_TREE_FREEBL_HEADERS_FIRST=1

export FREEBL_NO_DEPEND=1

export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
export NSPR_LIB_DIR=%{_libdir}

export NSS_USE_SYSTEM_SQLITE=1
export NSS_ALLOW_SSLKEYLOGFILE=1

%if %{with dbm}
%else
export NSS_DISABLE_DBM=1
%endif

%ifnarch noarch
%if 0%{__isa_bits} == 64
export USE_64=1
%endif
%endif


# Set the policy file location
# if set NSS will always check for the policy file and load if it exists
export POLICY_FILE="nss.config"
# location of the policy file
export POLICY_PATH="/etc/crypto-policies/back-ends"

make %{?_smp_mflags} -C ./nss all
make -C ./nss latest

# build the man pages clean
pushd ./nss
make clean_docs build_docs
popd

# and copy them to the dist directory for %%install to find them
mkdir -p ./dist/docs/nroff
cp ./nss/doc/nroff/* ./dist/docs/nroff

# Set up our package files
mkdir -p ./dist/pkgconfig
for m in %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4} %{SOURCE8} %{SOURCE9} %{SOURCE16}; do
  cp ${m} ./dist/pkgconfig
  chmod 755 ./dist/pkgconfig/*
done

NSSUTIL_VMAJOR=`cat nss/lib/util/nssutil.h | grep "#define.*NSSUTIL_VMAJOR" | awk '{print $3}'`
NSSUTIL_VMINOR=`cat nss/lib/util/nssutil.h | grep "#define.*NSSUTIL_VMINOR" | awk '{print $3}'`
NSSUTIL_VPATCH=`cat nss/lib/util/nssutil.h | grep "#define.*NSSUTIL_VPATCH" | awk '{print $3}'`

SOFTOKEN_VMAJOR=`cat nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VMAJOR" | awk '{print $3}'`
SOFTOKEN_VMINOR=`cat nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VMINOR" | awk '{print $3}'`
SOFTOKEN_VPATCH=`cat nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VPATCH" | awk '{print $3}'`

NSS_VMAJOR=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VMAJOR" | awk '{print $3}'`
NSS_VMINOR=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VMINOR" | awk '{print $3}'`
NSS_VPATCH=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VPATCH" | awk '{print $3}'`

cp ./nss/lib/ckfw/nssck.api ./dist/private/nss/

date +"%e %B %Y" | tr -d '\n' > date.xml
echo -n %{version} > version.xml

%if %{with test}
%check
export FREEBL_NO_DEPEND=1

export BUILD_OPT=1

%ifnarch noarch
%if 0%{__isa_bits} == 64
export USE_64=1
%endif
%endif

export NSS_IGNORE_SYSTEM_POLICY=1

# Run test suite.
SPACEISBAD=`find ./nss/tests | grep -c ' '` ||:
if [ $SPACEISBAD -ne 0 ]; then
  echo "error: filenames containing space are not supported (xargs)"
  exit 1
fi
MYRAND=`perl -e 'print 9000 + int rand 1000'`; echo $MYRAND ||:
RANDSERV=selfserv_${MYRAND}; echo $RANDSERV ||:
DISTBINDIR=`ls -d ./dist/*.OBJ/bin`; echo $DISTBINDIR ||:
pushd `pwd`
cd $DISTBINDIR
ln -s selfserv $RANDSERV
popd
# man perlrun, man perlrequick
# replace word-occurrences of selfserv with selfserv_$MYRAND
find ./nss/tests -type f |\
  grep -v "\.db$" |grep -v "\.crl$" | grep -v "\.crt$" |\
  grep -vw CVS  |xargs grep -lw selfserv |\
  xargs -l perl -pi -e "s/\bselfserv\b/$RANDSERV/g" ||:

killall $RANDSERV || :

rm -rf ./tests_results
pushd ./nss/tests/

#  the full list from all.sh is:
%define nss_tests "libpkix cert dbtests tools fips sdr crmf smime ssl ocsp merge pkits chains ec gtests ssl_gtests"
#  nss_ssl_tests: crl bypass_normal normal_bypass normal_fips fips_normal iopr policy
#  nss_ssl_run: cov auth stapling stress
#
# disable some test suites for faster test builds
# % define nss_ssl_tests "normal_fips"
# % define nss_ssl_run "cov"

HOST=localhost DOMSUF=localdomain PORT=$MYRAND NSS_CYCLES=%{?nss_cycles} NSS_TESTS=%{?nss_tests} NSS_SSL_TESTS=%{?nss_ssl_tests} NSS_SSL_RUN=%{?nss_ssl_run} ./all.sh

popd

killall $RANDSERV || :

TEST_FAILURES=$(grep -c -- '- FAILED$' ./tests_results/security/localhost.1/output.log) || GREP_EXIT_STATUS=$?

if [ ${GREP_EXIT_STATUS:-0} -eq 1 ]; then
  echo "okay: test suite detected no failures"
else
  if [ ${GREP_EXIT_STATUS:-0} -eq 0 ]; then
    # while a situation in which grep return status is 0 and it doesn't output
    # anything shouldn't happen, set the default to something that is
    # obviously wrong (-1)
    echo "error: test suite had ${TEST_FAILURES:--1} test failure(s)"
    exit 1
  else
    if [ ${GREP_EXIT_STATUS:-0} -eq 2 ]; then
      echo "error: grep has not found log file"
      exit 1
    else
      echo "error: grep failed with exit code: ${GREP_EXIT_STATUS}"
      exit 1
    fi
  fi
fi
echo "test suite completed"

%endif

%install

mkdir -p $RPM_BUILD_ROOT/%{_includedir}/nss3/templates
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{unsupported_tools_directory}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/nss/saved
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/prelink.conf.d/
mkdir -p $RPM_BUILD_ROOT/%{dracut_modules_dir}
mkdir -p $RPM_BUILD_ROOT/%{dracut_conf_dir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/crypto-policies/local.d
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man5
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb

# Install the empty NSS db files
# Legacy db
install -p -m 644 %{SOURCE10} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert8.db
install -p -m 644 %{SOURCE11} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key3.db
install -p -m 644 %{SOURCE12} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/secmod.db
# Shared db
install -p -m 644 %{SOURCE13} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert9.db
install -p -m 644 %{SOURCE14} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key4.db
install -p -m 644 %{SOURCE15} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/pkcs11.txt

# Copy the binary libraries we want
for file in libnssutil3.so libsoftokn3.so %{?with_dbm:libnssdbm3.so} libfreebl3.so libfreeblpriv3.so libnss3.so libnsssysinit.so libsmime3.so libssl3.so
do
  install -p -m 755 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the development libraries we want
for file in libcrmf.a libnssb.a libnssckfw.a libfreebl.a
do
  install -p -m 644 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the binaries we want
for file in certutil cmsutil crlutil modutil nss-policy-check pk12util signver ssltap
do
  install -p -m 755 dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{_bindir}
done

# Copy the binaries we ship as unsupported
for file in bltest ecperf fbectest fipstest shlibsign atob btoa derdump listsuites ocspclnt pp selfserv signtool strsclnt symkeyutil tstclnt vfyserv vfychain
do
  install -p -m 755 dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{unsupported_tools_directory}
done

# Copy the include files we want
for file in dist/public/nss/*.h
do
  install -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy some freebl include files we also want
for file in blapi.h alghmac.h cmac.h
do
  install -p -m 644 dist/private/nss/$file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy the template files we want
for file in dist/private/nss/templates.c dist/private/nss/nssck.api
do
  install -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3/templates
done

# Copy the package configuration files
install -p -m 644 ./dist/pkgconfig/nss-util.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss-util.pc
install -p -m 755 ./dist/pkgconfig/nss-util-config $RPM_BUILD_ROOT/%{_bindir}/nss-util-config
install -p -m 644 ./dist/pkgconfig/nss-softokn.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss-softokn.pc
install -p -m 755 ./dist/pkgconfig/nss-softokn-config $RPM_BUILD_ROOT/%{_bindir}/nss-softokn-config
install -p -m 644 ./dist/pkgconfig/nss.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss.pc
install -p -m 755 ./dist/pkgconfig/nss-config $RPM_BUILD_ROOT/%{_bindir}/nss-config
install -p -m 755 ./dist/pkgconfig/setup-nsssysinit.sh $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit.sh
ln -r -s -f $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit.sh $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit

# Copy the man pages for the nss tools
for f in "%{allTools}"; do
  install -c -m 644 ./dist/docs/nroff/${f}.1 $RPM_BUILD_ROOT%{_mandir}/man1/${f}.1
done
install -c -m 644 ./dist/docs/nroff/pp.1 $RPM_BUILD_ROOT%{_mandir}/man1/pp.1

# Copy the crypto-policies configuration file

#/usr/bin/setup-nsssysinit.sh on
#$RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libsoftokn3.so
#$RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libfreeblpriv3.so
#$RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libfreebl3.so
#$RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libnssdbm3.so

%post
update-crypto-policies &> /dev/null || :

%postun
update-crypto-policies &>/dev/null||:

%files
%{!?_licensedir:%global license %%doc}
%license nss/COPYING
%{_libdir}/libnss3.so
%{_libdir}/libssl3.so
%{_libdir}/libsmime3.so
%dir %{_sysconfdir}/pki/nssdb
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/*
%{_libdir}/libnsssysinit.so
%{_bindir}/setup-nsssysinit.sh
%{_bindir}/setup-nsssysinit

%files devel
%{_libdir}/libcrmf.a
%{_libdir}/pkgconfig/nss.pc
%{_bindir}/nss-config
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a

%dir %{_includedir}/nss3
%{_includedir}/nss3/cert*.h
%{_includedir}/nss3/cm*.h
%{_includedir}/nss3/cr*.h
%{_includedir}/nss3/sechash.h
%{_includedir}/nss3/jar-ds.h
%{_includedir}/nss3/jar.h
%{_includedir}/nss3/jarfile.h
%{_includedir}/nss3/key*.h
%{_includedir}/nss3/nss.h
%{_includedir}/nss3/ocsp.h
%{_includedir}/nss3/ocspt.h
%{_includedir}/nss3/p12.h
%{_includedir}/nss3/p12plcy.h
%{_includedir}/nss3/p12t.h
%{_includedir}/nss3/pk11*.h
%{_includedir}/nss3/pkcs12.h
%{_includedir}/nss3/pkcs12t.h
%{_includedir}/nss3/pkcs7t.h
%{_includedir}/nss3/preenc.h
%{_includedir}/nss3/secmime.h
%{_includedir}/nss3/secmod.h
%{_includedir}/nss3/secmodt.h
%{_includedir}/nss3/secpkcs5.h
%{_includedir}/nss3/secpkcs7.h
%{_includedir}/nss3/smime.h
%{_includedir}/nss3/ssl*.h
%{_includedir}/nss3/nssbase.h
%{_includedir}/nss3/nssbaset.h
%{_includedir}/nss3/nssck*.h
%{_includedir}/nss3/templates/nssck.api

%files util
%{!?_licensedir:%global license %%doc}
%license nss/COPYING
%{_libdir}/libnssutil3.so
%{_bindir}/certutil
%{_bindir}/cmsutil
%{_bindir}/crlutil
%{_bindir}/modutil
%{_bindir}/nss-policy-check
%{_bindir}/pk12util
%{_bindir}/signver
%{_bindir}/ssltap
%{unsupported_tools_directory}/atob
%{unsupported_tools_directory}/btoa
%{unsupported_tools_directory}/derdump
%{unsupported_tools_directory}/listsuites
%{unsupported_tools_directory}/ocspclnt
%{unsupported_tools_directory}/pp
%{unsupported_tools_directory}/selfserv
%{unsupported_tools_directory}/signtool
%{unsupported_tools_directory}/strsclnt
%{unsupported_tools_directory}/symkeyutil
%{unsupported_tools_directory}/tstclnt
%{unsupported_tools_directory}/vfyserv
%{unsupported_tools_directory}/vfychain

%files util-devel
%{_libdir}/pkgconfig/nss-util.pc
%{_bindir}/nss-util-config

# co-owned with nss
%dir %{_includedir}/nss3
# these are marked as public export in nss/lib/util/manifest.mk
%{_includedir}/nss3/base64.h
%{_includedir}/nss3/ciferfam.h
%{_includedir}/nss3/eccutil.h
%{_includedir}/nss3/hasht.h
%{_includedir}/nss3/nssb64.h
%{_includedir}/nss3/nssb64t.h
%{_includedir}/nss3/nsslocks.h
%{_includedir}/nss3/nssilock.h
%{_includedir}/nss3/nssilckt.h
%{_includedir}/nss3/nssrwlk.h
%{_includedir}/nss3/nssrwlkt.h
%{_includedir}/nss3/nssutil.h
%{_includedir}/nss3/pkcs1sig.h
%{_includedir}/nss3/pkcs11*.h
%{_includedir}/nss3/portreg.h
%{_includedir}/nss3/secasn1.h
%{_includedir}/nss3/secasn1t.h
%{_includedir}/nss3/seccomon.h
%{_includedir}/nss3/secder.h
%{_includedir}/nss3/secdert.h
%{_includedir}/nss3/secdig.h
%{_includedir}/nss3/secdigt.h
%{_includedir}/nss3/secerr.h
%{_includedir}/nss3/secitem.h
%{_includedir}/nss3/secoid.h
%{_includedir}/nss3/secoidt.h
%{_includedir}/nss3/secport.h
%{_includedir}/nss3/util*.h
%{_includedir}/nss3/templates/templates.c

%files softokn
%{!?_licensedir:%global license %%doc}
%license nss/COPYING
%{_libdir}/libfreebl3.so
#%{_libdir}/libfreebl3.chk
%{_libdir}/libfreeblpriv3.so
#%{_libdir}/libfreeblpriv3.chk
%if %{with dbm}
%{_libdir}/libnssdbm3.so
#%{_libdir}/libnssdbm3.chk
%endif
%{_libdir}/libsoftokn3.so
#%{_libdir}/libsoftokn3.chk
%dir %{_libdir}/nss
%dir %{_libdir}/nss/saved
%dir %{unsupported_tools_directory}
%{unsupported_tools_directory}/bltest
%{unsupported_tools_directory}/ecperf
%{unsupported_tools_directory}/fbectest
%{unsupported_tools_directory}/fipstest
%{unsupported_tools_directory}/shlibsign

%files softokn-devel
%{_libdir}/libfreebl.a
%{_includedir}/nss3/blapi.h
%{_includedir}/nss3/cmac.h
%{_includedir}/nss3/blapit.h
%{_includedir}/nss3/alghmac.h
%{_includedir}/nss3/lowkeyi.h
%{_includedir}/nss3/lowkeyti.h
%{_libdir}/pkgconfig/nss-softokn.pc
%{_bindir}/nss-softokn-config
# co-owned with nss
%dir %{_includedir}/nss3
%{_includedir}/nss3/ecl-exp.h
%{_includedir}/nss3/nsslowhash.h
%{_includedir}/nss3/shsign.h

%files help
%doc %{_mandir}/man*

%changelog
* Tue Dec 27 2022 zhouchenchen <zhouchenchen@huawei.com> - 3.85.0-1
- update source0 url

* Wed Nov 23 2022 zhouchenchen <zhouchenchen@huawei.com> - 3.72.0-6
- update source0 url

* Thu Oct 27 2022 luhuaxin <luhuaxin1@huawei.com> - 3.72.0-5
- optimize support for sm2,sm3 

* Mon Oct 10 2022 godcansee <liu332084460@foxmail.com> - 3.72.0-4
- add feature to support for sm2,sm3 

* Sat Jul 30 2022 zhangjun <zhangjun@kylinos.cn> - 3.72.0-3
- remove Requires nss-help 

* Tue Dec 28 2021 shangyibin <shangyibin1@huawei.com> - 3.72.0-2
- fix CVE-2021-43527

* Mon Nov 29 2021 liudabo <liudabo1@huawei.com> - 3.72.0-1
- upgrade version to 3.72

* Fri Jul 23 2021 yuanxin <yuanxin24@huawei.com> - 3.54-10
- remove BuildRequires gdb

* Wed Mar 17 2021 yixiangzhike <zhangxingliang3@huawei.com> - 3.54-9
- fix CVE-2020-12403

* Tue Mar 16 2021 yixiangzhike <zhangxingliang3@huawei.com> - 3.54-8
- optimize compilation time

* Tue Feb 9 2021 maminjie <maminjie1@huawei.com> - 3.54-7
- fix 0002-keygen-rsa hanging of certmonger

* Tue Jan 19 2021 zoulin <zoulin13@huawei.com> - 3.54-6
- fix CVE-2020-25648

* Wed Jan 6 2021 panxiaohe <panxiaohe@huawei.com> - 3.54-5
- fix nspr_version in spec 

* Tue Sep 22 2020 zhangxingliang <zhangxingliang3@huawei.com> - 3.54-4
- fix CVE-2020-6829 CVE-2020-12400 CVE-2020-12401

* Thu Aug 20 2020 Liquor <lirui130@huawei.com> - 3.54-3
- nss_version and pkg-version need to be consistent

* Sat Aug 1 2020 Liquor <lirui130@huawei.com> - 3.54-2
- add the missing header file and fixed error messages

* Sat Aug 1 2020 Liquor <lirui130@huawei.com> - 3.54-1
- update to 3.54

* Thu Apr 30 2020 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-12
- fix core dump when sigd-signerInfos is NULL

* Sat Mar 21 2020 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-11
- add BuildRequires of gdb; build without test

* Tue Feb 18 2020 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-10
- fix build error about setup-nsssysinit.sh

* Fri Feb 14 2020 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-9
- fix problem that tstclnt fails to connect to fe80::1%lo0

* Wed Jan 15 2020 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-8
- add nsssysinit.sh

* Sat Jan 11 2020 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-7
- simplify functions

* Tue Dec 31 2019 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-6
- delete unused man

* Mon Oct 14 2019 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-5
- add provide nss-pkcs11-devel

* Tue Sep 24 2019 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-4
- update requires for help

* Mon Sep 23 2019 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-3
- Rebuild

* Fri Sep 20 2019 openEuler Buildteam <buildteam@openeuler.org> - 3.40.1-2
- Package init
