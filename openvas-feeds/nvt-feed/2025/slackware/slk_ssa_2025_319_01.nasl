# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.319.01");
  script_cve_id("CVE-2024-2971", "CVE-2024-3247", "CVE-2024-3248", "CVE-2024-3900", "CVE-2024-4141", "CVE-2024-4568", "CVE-2024-4976", "CVE-2024-7866", "CVE-2024-7867", "CVE-2024-7868", "CVE-2025-11896", "CVE-2025-2574", "CVE-2025-3154");
  script_tag(name:"creation_date", value:"2025-11-17 04:09:07 +0000 (Mon, 17 Nov 2025)");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 12:40:01 +0000 (Wed, 11 Sep 2024)");

  script_name("Slackware: Security Advisory (SSA:2025-319-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-319-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.380759");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-2971");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-3247");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-3248");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-3900");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-4141");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-4568");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-4976");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-7866");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-7867");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-7868");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-11896");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-2574");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-3154");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xpdf' package(s) announced via the SSA:2025-319-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xpdf packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/xpdf-4.06-i586-1_slack15.0.txz: Upgraded.
 This update fixes bugs and security issues.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xpdf' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"4.06-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"4.06-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"4.06-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"4.06-x86_64-1", rls:"SLKcurrent"))) {
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
