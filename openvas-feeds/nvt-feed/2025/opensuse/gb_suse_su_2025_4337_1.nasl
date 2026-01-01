# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4337.1");
  script_cve_id("CVE-2025-61727", "CVE-2025-61729");
  script_tag(name:"creation_date", value:"2025-12-11 12:20:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4337-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254337-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254431");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023492.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.24' package(s) announced via the SUSE-SU-2025:4337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.24 fixes the following issues:

go1.24.11 (released 2025-12-02) includes two security fixes to the crypto/x509 package, as well as bug fixes to the runtime. (bsc#1236217)

CVE-2025-61727 CVE-2025-61729:

 * go#76460 go#76445 bsc#1254431 security: fix CVE-2025-61729 crypto/x509: excessive resource consumption in printing error string for host certificate validation
 * go#76463 go#76442 bsc#1254430 security: fix CVE-2025-61727 crypto/x509: excluded subdomain constraint doesn't preclude wildcard SAN

 * go#76378 internal/cpu: incorrect CPU features bit parsing on loong64 cause illegal instruction core dumps on LA364 cores

- Packaging: Migrate from update-alternatives to libalternatives (bsc#1245878)
 * This is an optional migration controlled via prjconf definition
 with_libalternatives
 * If with_libalternatives is not defined packaging continues to
 use update-alternatives");

  script_tag(name:"affected", value:"'go1.24' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.24", rpm:"go1.24~1.24.11~150000.1.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-doc", rpm:"go1.24-doc~1.24.11~150000.1.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-race", rpm:"go1.24-race~1.24.11~150000.1.50.1", rls:"openSUSELeap15.6"))) {
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
