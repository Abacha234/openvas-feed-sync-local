# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4148.1");
  script_cve_id("CVE-2025-59798", "CVE-2025-59799");
  script_tag(name:"creation_date", value:"2025-11-24 04:16:04 +0000 (Mon, 24 Nov 2025)");
  script_version("2025-11-24T05:41:47+0000");
  script_tag(name:"last_modification", value:"2025-11-24 05:41:47 +0000 (Mon, 24 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-25 19:28:52 +0000 (Thu, 25 Sep 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4148-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254148-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250354");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023308.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the SUSE-SU-2025:4148-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript fixes the following issues:

- CVE-2025-59798: Fixed stack-based buffer overflow in pdf_write_cmap in devices/vector/gdevpdtw.c. (bsc#1250353)
- CVE-2025-59799: Fixed stack-based buffer overflow in pdfmark_coerce_dest in devices/vector/gdevpdfm.c via a large size value. (bsc#1250354)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.52~150000.211.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.52~150000.211.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.52~150000.211.1", rls:"openSUSELeap15.6"))) {
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
