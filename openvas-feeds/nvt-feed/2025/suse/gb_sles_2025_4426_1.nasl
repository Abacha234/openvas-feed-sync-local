# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4426.1");
  script_cve_id("CVE-2018-15853", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15863");
  script_tag(name:"creation_date", value:"2025-12-19 04:23:19 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-23 16:47:02 +0000 (Tue, 23 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4426-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254426-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105832");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023569.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xkbcomp' package(s) announced via the SUSE-SU-2025:4426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xkbcomp fixes the following issues:

- CVE-2018-15863: NULL pointer dereference triggered by a a crafted keymap file with a no-op modmask expression can
 lead to a crash (bsc#1105832).
- CVE-2018-15861: NULL pointer dereference triggered by a crafted keymap file that induces an `xkb_intern_atom` failure
 can lead to a crash (bsc#1105832).
- CVE-2018-15859: NULL pointer dereference triggered by a specially a crafted keymap file can lead to a crash
 (bsc#1105832).
- CVE-2018-15853: endless recursion triggered by a crafted keymap file that induces boolean negation can lead to a
 crash (bsc#1105832).");

  script_tag(name:"affected", value:"'xkbcomp' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp", rpm:"xkbcomp~1.4.1~150000.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp-devel", rpm:"xkbcomp-devel~1.4.1~150000.3.6.1", rls:"SLES15.0SP6"))) {
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
