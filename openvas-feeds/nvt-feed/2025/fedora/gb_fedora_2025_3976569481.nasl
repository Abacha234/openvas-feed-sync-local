# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3976569481");
  script_cve_id("CVE-2025-4437", "CVE-2025-47906", "CVE-2025-47910");
  script_tag(name:"creation_date", value:"2025-10-13 04:05:45 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-20 13:15:28 +0000 (Wed, 20 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-3976569481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3976569481");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3976569481");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333357");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375096");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398408");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398663");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399065");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399339");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cri-o1.33' package(s) announced via the FEDORA-2025-3976569481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v1.33.5
- Resolves: rhbz#2333357, rhbz#2375096, rhbz#2398408, rhbz#2398663,
 rhbz#2399065, rhbz#2399339
- Upstream fixes");

  script_tag(name:"affected", value:"'cri-o1.33' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.33", rpm:"cri-o1.33~1.33.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.33-debuginfo", rpm:"cri-o1.33-debuginfo~1.33.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.33-debugsource", rpm:"cri-o1.33-debugsource~1.33.5~1.fc41", rls:"FC41"))) {
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
