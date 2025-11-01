# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98101979859821015101");
  script_cve_id("CVE-2024-50345");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-04 16:09:49 +0000 (Thu, 04 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-beab5b2e5e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-beab5b2e5e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-beab5b2e5e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2324262");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336564");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud' package(s) announced via the FEDORA-2025-beab5b2e5e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for nextcloud-31.0.0-1.fc43.

##### **Changelog**

```
* Sun Mar 2 2025 Andrew Bauer <zonexpertconsulting@outlook.com> - 31.0.0-1
- 31.0.0 release RHBZ#2324262 RHBZ#2336564
* Fri Feb 7 2025 Andrew Bauer <zonexpertconsulting@outlook.com> - 30.0.5-4
- escape period
* Mon Feb 3 2025 Andrew Bauer <zonexpertconsulting@outlook.com> - 30.0.5-3
- use composer-generators to autogenerate php-composer provides

```");

  script_tag(name:"affected", value:"'nextcloud' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~31.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-httpd", rpm:"nextcloud-httpd~31.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-mysql", rpm:"nextcloud-mysql~31.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-nginx", rpm:"nextcloud-nginx~31.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-postgresql", rpm:"nextcloud-postgresql~31.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-sqlite", rpm:"nextcloud-sqlite~31.0.0~1.fc43", rls:"FC43"))) {
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
