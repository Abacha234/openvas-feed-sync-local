# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10232981100101981008");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-f32b1debd8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f32b1debd8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f32b1debd8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398589");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398850");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399251");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399524");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407790");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408060");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408317");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408611");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408674");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408732");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409239");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409529");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409790");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410204");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410479");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410740");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411120");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411378");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411636");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412590");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412805");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.34' package(s) announced via the FEDORA-2025-f32b1debd8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v1.34.2
- Resolves: rhbz#2398589, rhbz#2398850, rhbz#2399251, rhbz#2399524
- Resolves: rhbz#2407790, rhbz#2408060, rhbz#2408317, rhbz#2408611
- Resolves: rhbz#2408674, rhbz#2408732, rhbz#2409239, rhbz#2409529
- Resolves: rhbz#2409790, rhbz#2410204, rhbz#2410479, rhbz#2410740
- Resolves: rhbz#2411120, rhbz#2411378, rhbz#2411636 rhbz#2412590
- Resolves: rhbz#2412805
- Upstream fixes");

  script_tag(name:"affected", value:"'kubernetes1.34' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.34", rpm:"kubernetes1.34~1.34.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.34-client", rpm:"kubernetes1.34-client~1.34.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.34-kubeadm", rpm:"kubernetes1.34-kubeadm~1.34.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.34-systemd", rpm:"kubernetes1.34-systemd~1.34.2~1.fc43", rls:"FC43"))) {
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
