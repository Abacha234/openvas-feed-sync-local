# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3943.1");
  script_cve_id("CVE-2024-28885", "CVE-2024-31074", "CVE-2024-33617");
  script_tag(name:"creation_date", value:"2025-11-06 14:19:04 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3943-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3943-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253943-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233366");
  script_xref(name:"URL", value:"https://github.com/intel/qatlib#resolved-issues");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023159.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qatengine, qatlib' package(s) announced via the SUSE-SU-2025:3943-1 advisory.");

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

qatlib was updated to 24.09.0:

 * Improved performance scaling in multi-thread applications
 * Set core affinity mapping based on NUMA
 (libnuma now required for building)
 * bug fixes, see [link moved to references]

version update to 24.02.0:

 * Support DC NS (NoSession) APIs
 * Support Symmetric Crypto SM3 & SM4
 * Support Asymmetric Crypto SM2
 * Support DC CompressBound APIs
 * Bug Fixes. See Resolved section in README.md

update to 23.11.0:

 * use new --enable-legacy-algorithms to avoid regressions
 * add support for data compression chaining (hash then compress)
 * add support for additional configuration profiles
 * add support DC NS (NoSession) APIs
 * add support DC CompressBound APIs
 * add Support for Chinese SM{2,3,4} ciphers
 * bump shared library major to 4
 * refactoring, bug fixes and documentation updates");

  script_tag(name:"affected", value:"'qatengine, qatlib' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libqat4", rpm:"libqat4~24.09.0~150500.3.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqatzip3", rpm:"libqatzip3~1.1.0~150500.3.2.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libusdm0", rpm:"libusdm0~24.09.0~150500.3.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatengine", rpm:"qatengine~1.7.0~150500.3.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib", rpm:"qatlib~24.09.0~150500.3.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatlib-devel", rpm:"qatlib-devel~24.09.0~150500.3.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatzip", rpm:"qatzip~1.1.0~150500.3.2.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qatzip-devel", rpm:"qatzip-devel~1.1.0~150500.3.2.1", rls:"SLES15.0SP5"))) {
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
