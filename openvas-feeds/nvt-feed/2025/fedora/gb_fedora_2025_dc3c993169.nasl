# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10099399993169");
  script_cve_id("CVE-2025-58185", "CVE-2025-58189", "CVE-2025-61723");
  script_tag(name:"creation_date", value:"2025-12-02 04:12:50 +0000 (Tue, 02 Dec 2025)");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-dc3c993169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-dc3c993169");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-dc3c993169");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337561");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408351");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409823");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410773");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'source-to-image' package(s) announced via the FEDORA-2025-dc3c993169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.5.1, migrate to Go Vendor Tools");

  script_tag(name:"affected", value:"'source-to-image' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"source-to-image", rpm:"source-to-image~1.5.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"source-to-image-debuginfo", rpm:"source-to-image-debuginfo~1.5.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"source-to-image-debugsource", rpm:"source-to-image-debugsource~1.5.1~1.fc43", rls:"FC43"))) {
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
