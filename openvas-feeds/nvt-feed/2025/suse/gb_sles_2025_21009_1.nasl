# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21009.1");
  script_cve_id("CVE-2024-13978", "CVE-2025-8176", "CVE-2025-8177", "CVE-2025-8534", "CVE-2025-8961", "CVE-2025-9165", "CVE-2025-9900");
  script_tag(name:"creation_date", value:"2025-11-28 04:13:19 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-23 17:15:38 +0000 (Tue, 23 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21009-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521009-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250413");
  script_xref(name:"URL", value:"https://github.com/OSGeo/gdal/issues/10875");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023383.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2025:21009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

tiff was updated to 4.7.1:

* Software configuration changes:

 * Define HAVE_JPEGTURBO_DUAL_MODE_8_12 and LERC_STATIC in tif_config.h.
 * CMake: define WORDS_BIGENDIAN via tif_config.h
 * doc/CMakeLists.txt: remove useless cmake_minimum_required()
 * CMake: fix build with LLVM/Clang 17 (fixes issue #651)
 * CMake: set CMP0074 new policy
 * Set LINKER_LANGUAGE for C targets with C deps
 * Export tiffxx cmake target (fixes issue #674)
 * autogen.sh: Enable verbose wget.
 * configure.ac: Syntax updates for Autoconf 2.71
 * autogen.sh: Re-implement based on autoreconf. Failure to update
 config.guess/config.sub does not return error (fixes issue #672)
 * CMake: fix CMake 4.0 warning when minimum required version is < 3.10.
 * CMake: Add build option tiff-static (fixes issue #709)
 Library changes:
 * Add TIFFOpenOptionsSetWarnAboutUnknownTags() for explicit control
 about emitting warnings for unknown tags. No longer emit warnings
 about unknown tags by default
 * tif_predict.c: speed-up decompression in some cases.

* Bug fixes:

 * tif_fax3: For fax group 3 data if no EOL is detected, reading is
 retried without synchronisation for EOLs. (fixes issue #54)
 * Updating TIFFMergeFieldInfo() with read_count=write_count=0 for
 FIELD_IGNORE. Updating TIFFMergeFieldInfo() with read_count=write_count=0 for
 FIELD_IGNORE. Improving handling when field_name = NULL. (fixes issue #532)
 * tiff.h: add COMPRESSION_JXL_DNG_1_7=52546 as used for JPEGXL compression in
 the DNG 1.7 specification
 * TIFFWriteDirectorySec: Increment string length for ASCII tags for codec tags
 defined with FIELD_xxx bits, as it is done for FIELD_CUSTOM tags. (fixes issue #648)
 * Do not error out on a tag whose tag count value is zero, just issue a warning.
 Fix parsing a private tag 0x80a6 (fixes issue #647)
 * TIFFDefaultTransferFunction(): give up beyond td_bitspersample = 24
 Fixes [link moved to references])
 * tif_getimage.c: Remove unnecessary calls to TIFFRGBAImageOK() (fixes issue #175)
 * Fix writing a Predictor=3 file with non-native endianness
 * _TIFFVSetField(): fix potential use of unallocated memory (out-of-bounds
 * read / nullptr dereference) in case of out-of-memory situation when dealing with
 custom tags (fixes issue #663)
 * tif_fax3.c: Error out for CCITT fax encoding if SamplesPerPixel is not equal 1 and
 PlanarConfiguration = Contiguous (fixes issue #26)
 * tif_fax3.c: error out after a number of times end-of-line or unexpected bad code
 words have been reached. (fixes issue #670)
 * Fix memory leak in TIFFSetupStrips() (fixes issue #665)
 * tif_zip.c: Provide zlib allocation functions. Otherwise for zlib built with
 -DZ_SOLO inflating will fail.
 * Fix memory leak in _TIFFSetDefaultCompressionState. (fixes issue #676)
 * tif_predict.c: Don't overwrite input buffer of TIFFWriteScanline() if 'prediction'
 is enabled. Use extra working ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.7.1~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff6", rpm:"libtiff6~4.7.1~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.7.1~160000.1.1", rls:"SLES16.0.0"))) {
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
