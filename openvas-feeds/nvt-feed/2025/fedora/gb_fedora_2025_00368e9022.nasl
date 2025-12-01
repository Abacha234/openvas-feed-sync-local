# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.003681019022");
  script_cve_id("CVE-2025-11065", "CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-00368e9022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-00368e9022");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-00368e9022");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398587");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398848");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399249");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399522");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399721");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407788");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408058");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408315");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408609");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408672");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408730");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409237");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409527");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409788");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410202");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410738");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411117");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411376");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411634");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412569");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412588");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412803");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2414539");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.32' package(s) announced via the FEDORA-2025-00368e9022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v1.32.10
- Resolves: rhbz#2414539
- Resolves: rhbz#2398587, rhbz#2398848, rhbz#2399249, rhbz#2399522
- Resolves: rhbz#2399703, rhbz#2399721, rhbz#2407788, rhbz#2408058
- Resolves: rhbz#2408315, rhbz#2408609, rhbz#2408672, rhbz#2408730
- Resolves: rhbz#2409237, rhbz#2409527, rhbz#2409788, rhbz#2410202
- Resolves: rhbz#2410477, rhbz#2410738, rhbz#2411117, rhbz#2411376
- Resolves: rhbz#2411634, rhbz#2412569, rhbz#2412588, rhbz#2412803
- Upstream fixes");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32", rpm:"kubernetes1.32~1.32.10~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32-client", rpm:"kubernetes1.32-client~1.32.10~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32-kubeadm", rpm:"kubernetes1.32-kubeadm~1.32.10~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.32-systemd", rpm:"kubernetes1.32-systemd~1.32.10~2.fc43", rls:"FC43"))) {
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
