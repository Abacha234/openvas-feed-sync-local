# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4247.1");
  script_cve_id("CVE-2025-11561");
  script_tag(name:"creation_date", value:"2025-11-28 04:08:19 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-09 14:15:54 +0000 (Thu, 09 Oct 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4247-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254247-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251827");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023368.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the SUSE-SU-2025:4247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sssd fixes the following issues:

 - CVE-2025-11561: Fixed privilege escalation on AD-joined Linux systems due
 to default Kerberos configuration disabling localauth an2ln plugin (bsc#1251827)");

  script_tag(name:"affected", value:"'sssd' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0", rpm:"libipa_hbac0~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnfsidmap-sss", rpm:"libnfsidmap-sss~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0", rpm:"libsss_certmap0~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0", rpm:"libsss_idmap0~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0", rpm:"libsss_nss_idmap0~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0", rpm:"libsss_simpleifp0~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipa_hbac", rpm:"python3-ipa_hbac~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss-murmur", rpm:"python3-sss-murmur~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sss_nss_idmap", rpm:"python3-sss_nss_idmap~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config", rpm:"python3-sssd-config~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-32bit", rpm:"sssd-32bit~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-kcm", rpm:"sssd-kcm~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap", rpm:"sssd-winbind-idmap~2.9.3~150600.3.28.1", rls:"openSUSELeap15.6"))) {
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
