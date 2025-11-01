# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.025971021029420");
  script_cve_id("CVE-2024-40635", "CVE-2025-22870", "CVE-2025-22872");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-23 15:09:09 +0000 (Tue, 23 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-025aff9420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-025aff9420");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-025aff9420");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352158");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2353097");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2360592");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367247");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-compose' package(s) announced via the FEDORA-2025-025aff9420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for docker-compose-2.36.1-1.fc43.

##### **Changelog**

```
* Mon May 19 2025 Bradley G Smith <bradley.g.smith@gmail.com> - 2.36.1-1
- Update to release v2.36.1
- Resolves: rhbz#2367247, rhbz#2360592, rhbz#2353097, rhbz#2352158
- Improvements and fixes. See upstream changelog

```");

  script_tag(name:"affected", value:"'docker-compose' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-compose", rpm:"docker-compose~2.36.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-compose-debuginfo", rpm:"docker-compose-debuginfo~2.36.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-compose-debugsource", rpm:"docker-compose-debugsource~2.36.1~1.fc43", rls:"FC43"))) {
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
