# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21211.1");
  script_cve_id("CVE-2025-55212", "CVE-2025-55298", "CVE-2025-57803", "CVE-2025-57807", "CVE-2025-62171", "CVE-2025-62594");
  script_tag(name:"creation_date", value:"2025-12-19 15:00:01 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-10 15:31:10 +0000 (Wed, 10 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21211-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21211-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521211-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252749");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023597.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2025:21211-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2025-62594: unsigned underflow and division-by-zero can lead to OOB pointer arithmetic and process crash
 (bsc#1252749).
- CVE-2025-57807: BlobStream Forward-Seek Under-Allocation (bsc#1249362).
- CVE-2025-62171: incomplete fix for integer overflow in BMP Decoder (bsc#1252282).
- CVE-2025-55298: format string bug vulnerability can lead to heap overflow (bsc#1248780).
- CVE-2025-57803: 32-bit integer overflow can lead to heap out-of-bounds (OOB) write (bsc#1248784).
- CVE-2025-55212: division-by-zero in ThumbnailImage() when passing a geometry string containing only a colon to
 `montage -geometry` (bsc#1248767).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-limited", rpm:"ImageMagick-config-7-upstream-limited~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-open", rpm:"ImageMagick-config-7-upstream-open~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-secure", rpm:"ImageMagick-config-7-upstream-secure~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-websafe", rpm:"ImageMagick-config-7-upstream-websafe~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5", rpm:"libMagick++-7_Q16HDRI5~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10", rpm:"libMagickCore-7_Q16HDRI10~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10", rpm:"libMagickWand-7_Q16HDRI10~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.1.2.0~160000.4.1", rls:"SLES16.0.0"))) {
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
