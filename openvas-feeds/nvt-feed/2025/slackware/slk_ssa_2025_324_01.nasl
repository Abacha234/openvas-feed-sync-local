# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.324.01");
  script_cve_id("CVE-2025-9820");
  script_tag(name:"creation_date", value:"2025-11-21 04:05:39 +0000 (Fri, 21 Nov 2025)");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-324-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-324-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.379440");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-9820");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SSA:2025-324-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gnutls packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/gnutls-3.8.11-i586-1_slack15.0.txz: Upgraded.
 This update fixes a security issue:
 libgnutls: Fix stack overwrite in gnutls_pkcs11_token_init.
 Reported by Luigino Camastra from Aisle Research.
 Upstream says this is low severity because the PKCS#11 standard defines a
 size limit of 32 characters, and therefore it's the application's fault if
 it doesn't check that and reject a longer label. I'm not buying that.
 NOTE: Be sure to also install the nettle upgrade.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/nettle-3.10.2-i586-1_slack15.0.txz: Upgraded.
 This update is required by gnutls-3.8.11.
+--------------------------+");

  script_tag(name:"affected", value:"'gnutls' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.11-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.11-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.11-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"3.8.11-x86_64-1", rls:"SLKcurrent"))) {
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
