# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833188");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4039");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 20:01:22 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:46:26 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gcc13 (SUSE-SU-2023:4162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4162-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YOFUKXJH42YHQ7HQMK3LB2WRG3BATX3G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc13'
  package(s) announced via the SUSE-SU-2023:4162-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gcc13 fixes the following issues:

  This update ship the GCC 13.2 compiler suite and its base libraries.

  The compiler base libraries are provided for all SUSE Linux Enterprise 15
  versions and replace the same named GCC 12 ones.

  The new compilers for C, C++, and Fortran are provided for SUSE Linux Enterprise
  15 SP4 and SP5, and provided in the 'Development Tools' module.

  The Go, D, Ada and Modula 2 language compiler parts are available unsupported
  via the PackageHub repositories.

  To use gcc13 compilers use:

  * install 'gcc13' or 'gcc13-c++' or one of the other 'gcc13-COMPILER' frontend
      packages.

  * override your Makefile to use CC=gcc13, CXX=g++13 and similar overrides for
      the other languages.

  Detailed changes:

  * CVE-2023-4039: Fixed -fstack-protector issues on aarch64 with variable
      length stack allocations. (bsc#1214052)

  * Turn cross compiler to s390x to a glibc cross. [bsc#1214460]

  * Also handle -static-pie in the default-PIE specs

  * Fixed missed optimization in Skia resulting in Firefox crashes when building
      with LTO. [bsc#1212101]

  * Make libstdc++6-devel packages own their directories since they can be
      installed standalone. [bsc#1211427]

  * Add new x86-related intrinsics (amxcomplexintrin.h).

  * RISC-V: Add support for inlining subword atomic operations

  * Use --enable-link-serialization rather that --enable-link-mutex, the benefit
      of the former one is that the linker jobs are not holding tokens of the
      make's jobserver.
      general state of BPF with GCC.

  * Add bootstrap conditional to allow --without=bootstrap to be specified to
      speed up local builds for testing.

  * Bump included newlib to version 4.3.0.

  * Also package libhwasan_preinit.o on aarch64.

  * Configure external timezone database provided by the timezone package. Make
      libstdc++6 recommend timezone to get a fully working std::chrono. Install
      timezone when running the testsuite.

  * Package libhwasan_preinit.o on x86_64.

  * Fixed unwinding on aarch64 with pointer signing. [bsc#1206684]

  * Enable PRU flavour for gcc13

  * update floatn fixinclude pickup to check each header separately
      (bsc#1206480)

  * Redo floatn fixinclude pick-up to simply keep what is there.

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'gcc13' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
