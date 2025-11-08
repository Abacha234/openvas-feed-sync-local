# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3942.1");
  script_cve_id("CVE-2024-28885", "CVE-2024-31074", "CVE-2024-33617");
  script_tag(name:"creation_date", value:"2025-11-06 14:19:04 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3942-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3942-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253942-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233366");
  script_xref(name:"URL", value:"https://github.com/intel/qatlib#resolved-issues");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023160.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qatengine, qatlib' package(s) announced via the SUSE-SU-2025:3942-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qatengine, qatlib fixes the following issues:

Note that the 1.6.1 release included in 1.7.0 fixes the following vulnerabilities:

 * bsc#1233363 (CVE-2024-28885)
 * bsc#1233365 (CVE-2024-31074)
 * bsc#1233366 (CVE-2024-33617)

Update to 1.7.0:

 * ipp-crypto name change to cryptography-primitives
 * QAT_SW GCM memory leak fix in cleanup function
 * Update limitation section in README for v1.7.0 release
 * Fix build with OPENSSL_NO_ENGINE
 * Fix for build issues with qatprovider in qatlib
 * Bug fixes and README updates to v1.7.0
 * Remove qat_contig_mem driver support
 * Add support for building QAT Engine ENGINE and PROVIDER modules
 with QuicTLS 3.x libraries
 * Fix for DSA issue with openssl3.2
 * Fix missing lower bounds check on index i
 * Enabled SW Fallback support for FBSD
 * Fix for segfault issue when SHIM config section is unavailable
 * Fix for Coverity & Resource leak
 * Fix for RSA failure with SVM enabled in openssl-3.2
 * SM3 Memory Leak Issue Fix
 * Fix qatprovider lib name issue with system openssl

Update to 1.6.0:

 * Fix issue with make depend for QAT_SW
 * QAT_HW GCM Memleak fix & bug fixes
 * QAT2.0 FreeBSD14 intree driver support
 * Fix OpenSSL 3.2 compatibility issues
 * Optimize hex dump logging
 * Clear job tlv on error
 * QAT_HW RSA Encrypt and Decrypt provider support
 * QAT_HW AES-CCM Provider support
 * Add ECDH keymgmt support for provider
 * Fix QAT_HW SM2 memory leak
 * Enable qaeMemFreeNonZeroNUMA() for qatlib
 * Fix polling issue for the process that doesn't have QAT_HW instance
 * Fix SHA3 qctx initialization issue & potential memleak
 * Fix compilation error in SM2 with qat_contig_mem
 * Update year in copyright information to 2024

Update to 1.5.0:

 * use new --enable-qat_insecure_algorithms to avoid regressions
 * improve support for SM{2,3,4} ciphers
 * improve SW fallback support
 * many bug fixes, refactorisations and documentation updates

- update to 0.6.18:
 * Fix address sanitizer issues
 * Fix issues with Babassl & Openssl3.0
 * Add QAT_HW SM4 CBC support
 * Refactor ECX provider code into single file
 * Fix QAT_HW AES-GCM bad mac record & memleak
 * Fix SHA3 memory leak
 * Fix sm4-cbc build error with system default OpenSSL
 * Symmetric performance Optimization & memleak fixes
 * Bug fix, README & v0.6.18 Version update
 * Please refer README (Software requirements section) for dependent
 libraries release version and other information.

- update to v0.6.17:
 * Add security policy - c1a7a96
 * Add dependancy update tool file - 522c41d
 * Release v0.6.17 version update - c1a7a96
 * Enable QAT_SW RSA & ECDSA support for BoringSSL - 1035e82
 * Fix QAT_SW SM2 ECDSA Performance issue - f44a564
 * CPP check and Makefile Bug fixes - 98ccbe8
 * Fix buffer overflow issue with SHA3 and ECX - cab65f3
 * Update version and README for v0.6.16 - 1c95fd7
 * Split --with-qat_sw_install_dir into seperate configures - ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qatengine, qatlib' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libqat4", rpm:"libqat4~24.09.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqatzip3", rpm:"libqatzip3~1.1.0~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusdm0", rpm:"libusdm0~24.09.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatengine", rpm:"qatengine~1.7.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib", rpm:"qatlib~24.09.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib-devel", rpm:"qatlib-devel~24.09.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatzip", rpm:"qatzip~1.1.0~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatzip-devel", rpm:"qatzip-devel~1.1.0~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
