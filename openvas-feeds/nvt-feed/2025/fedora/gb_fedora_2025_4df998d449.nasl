# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.4100102998100449");
  script_cve_id("CVE-2025-4563");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-4df998d449)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-4df998d449");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4df998d449");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373847");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373848");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.32' package(s) announced via the FEDORA-2025-4df998d449 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for kubernetes1.32-1.32.6-1.fc43.

##### **Changelog**

```
* Thu Jun 19 2025 Bradley G Smith <bradley.g.smith@gmail.com> - 1.32.6-1
- Update to release v1.32.6
- Resolves: rhbz#2373848,rhbz#2373847
- Resolves: CVE-2025-4563
- Upstream fixes and cleanups

```");

  script_tag(name:"affected", value:"'kubernetes1.32' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32", rpm:"kubernetes1.32~1.32.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32-client", rpm:"kubernetes1.32-client~1.32.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32-kubeadm", rpm:"kubernetes1.32-kubeadm~1.32.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32-systemd", rpm:"kubernetes1.32-systemd~1.32.6~1.fc43", rls:"FC43"))) {
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
