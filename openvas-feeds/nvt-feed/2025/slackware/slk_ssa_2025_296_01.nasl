# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.296.01");
  script_cve_id("CVE-2025-9230");
  script_tag(name:"creation_date", value:"2025-10-24 04:06:03 +0000 (Fri, 24 Oct 2025)");
  script_version("2025-10-24T05:39:31+0000");
  script_tag(name:"last_modification", value:"2025-10-24 05:39:31 +0000 (Fri, 24 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-296-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2025-296-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.398903");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-9230");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2025-296-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 15.0 to fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/openssl-1.1.1zd-i586-1_slack15.0.txz: Upgraded.
 Apply patch to fix a moderate severity security issue:
 Fix incorrect check of unwrapped key size in kek_unwrap_key()
 The check is off by 8 bytes so it is possible to overread by up to 8 bytes
 and overwrite up to 4 bytes.
 Although the consequences of a successful exploit of this vulnerability
 could be severe, the probability that the attacker would be able to perform
 it is low. Besides, password based (PWRI) encryption support in CMS
 messages is very rarely used.
 This CVE was fixed by the 1.1.1zd release that is only available to
 subscribers to OpenSSL's premium extended support. The patch was prepared
 by backporting from the OpenSSL-3.0 repo.
 Thanks to Ken Zalewski for the patch!
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/openssl-solibs-1.1.1zd-i586-1_slack15.0.txz: Upgraded.
+--------------------------+");

  script_tag(name:"affected", value:"'openssl' package(s) on Slackware 15.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1zd-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1zd-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1zd-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1zd-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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
