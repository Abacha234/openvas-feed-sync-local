# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.41029510216098101");
  script_cve_id("CVE-2023-52353", "CVE-2024-23744");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 16:00:24 +0000 (Mon, 29 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-4f95f160be)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-4f95f160be");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4f95f160be");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259499");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259505");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2340849");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359781");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_42_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'micropython' package(s) announced via the FEDORA-2025-4f95f160be advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for micropython-1.25.0-1.fc43.

##### **Changelog**

```
* Fri May 9 2025 Charalampos Stratakis <cstratak@redhat.com> - 1.25.0-1
- Update to 1.25.0
- Security fixes for CVE-2023-52353 and CVE-2024-23744 in mbedtls
- Fix FTBFS with GCC 15
Resolves: rhbz#2359781, rhbz#2259505, rhbz#2259499, rhbz#2340849
* Fri Jan 17 2025 Fedora Release Engineering <releng@fedoraproject.org> - 1.24.1-2
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'micropython' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"micropython", rpm:"micropython~1.25.0~1.fc43", rls:"FC43"))) {
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
