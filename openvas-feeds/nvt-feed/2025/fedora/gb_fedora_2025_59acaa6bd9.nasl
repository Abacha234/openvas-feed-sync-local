# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.59979997976981009");
  script_cve_id("CVE-2025-22870");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-59acaa6bd9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-59acaa6bd9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-59acaa6bd9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2061180");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352162");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_43_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffuf' package(s) announced via the FEDORA-2025-59acaa6bd9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for ffuf-2.1.0-1.fc43.

##### **Changelog**

```
* Wed Aug 13 2025 Sandipan Roy <sandipan@redhat.com> - 2.1.0-1
- Update to version 2.1.0
- Update to 2.1.0 - Closes rhbz#2061180 rhbz#2352162
- Implement vendoring approach using go2rpm with vendor archive
- Add all Go dependencies bundled for offline builds in mock/koji
- Use rpmautospec for automatic release and changelog management
- Re-enable tests with selective skipping for TestToCSV failure only
- Update license to include all vendored dependency licenses: Apache-2.0
 AND BSD-2-Clause AND BSD-3-Clause AND MIT
- Preserve complete historical changelog from package inception
* Wed Jul 23 2025 Fedora Release Engineering <releng@fedoraproject.org> - 1.0.2-17
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'ffuf' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"ffuf", rpm:"ffuf~2.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffuf-debuginfo", rpm:"ffuf-debuginfo~2.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffuf-debugsource", rpm:"ffuf-debugsource~2.1.0~1.fc43", rls:"FC43"))) {
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
