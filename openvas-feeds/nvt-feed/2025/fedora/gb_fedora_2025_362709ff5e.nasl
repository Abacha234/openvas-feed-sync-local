# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3627091021025101");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-362709ff5e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-362709ff5e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-362709ff5e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398588");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398849");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399250");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399523");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407789");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408059");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408316");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408610");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408673");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408731");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409238");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409528");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409789");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410203");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410478");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410739");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411118");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411377");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412570");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412589");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412804");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.33' package(s) announced via the FEDORA-2025-362709ff5e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v1.33.6
- Resolves: rhbz#2398588, rhbz#2398849, rhbz#2399250, rhbz#2399523
- Resolves: rhbz#2407789, rhbz#2408059, rhbz#2408316, rhbz#2408610
- Resolves: rhbz#2408673, rhbz#2408731, rhbz#2409238, rhbz#2409528
- Resolves: rhbz#2409789, rhbz#2410203, rhbz#2410478, rhbz#2410739
- Resolves: rhbz#2411118, rhbz#2411377, rhbz#2412570, rhbz#2412589
- Resolves: rhbz#2412804
- Upstream fixes");

  script_tag(name:"affected", value:"'kubernetes1.33' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.33", rpm:"kubernetes1.33~1.33.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.33-client", rpm:"kubernetes1.33-client~1.33.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.33-kubeadm", rpm:"kubernetes1.33-kubeadm~1.33.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.33-systemd", rpm:"kubernetes1.33-systemd~1.33.6~1.fc42", rls:"FC42"))) {
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
