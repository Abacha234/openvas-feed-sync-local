# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.3699.1");
  script_cve_id("CVE-2025-3576");
  script_tag(name:"creation_date", value:"2025-10-23 04:06:50 +0000 (Thu, 23 Oct 2025)");
  script_version("2025-10-24T05:39:31+0000");
  script_tag(name:"last_modification", value:"2025-10-24 05:39:31 +0000 (Fri, 24 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 06:15:44 +0000 (Tue, 15 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:3699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3699-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253699-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241219");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042240.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the SUSE-SU-2025:3699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for krb5 fixes the following issues:

- CVE-2025-3576: weakness in the MD5 checksum design allows for spoofing of GSSAPI-protected messages that are using
 RC4-HMAC-MD5 (bsc#1241219).

Krb5 as very old protocol supported quite a number of ciphers that are not longer up to current cryptographic standards.

To avoid problems with those, SUSE has by default now disabled those alorithms.

The following algorithms have been removed from valid krb5 enctypes:

- des3-cbc-sha1
- arcfour-hmac-md5

To reenable those algorithms, you can use allow options in krb5.conf:

[libdefaults]
allow_des3 = true allow_rc4 = true

to reenable them.");

  script_tag(name:"affected", value:"'krb5' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-spake", rpm:"krb5-plugin-preauth-spake~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.20.1~150600.11.14.1", rls:"openSUSELeap15.6"))) {
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
