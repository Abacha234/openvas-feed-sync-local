# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8971024100101010283");
  script_cve_id("CVE-2025-54880", "CVE-2025-54881");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-20 15:12:18 +0000 (Mon, 20 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-8af4de0f83)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-8af4de0f83");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-8af4de0f83");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388493");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389814");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389815");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389830");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389831");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389842");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389843");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud' package(s) announced via the FEDORA-2025-8af4de0f83 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"31.0.9 release RHBZ#2388493 RHBZ#2389830 RHBZ#2389831 RHBZ#2389842 RHBZ#2389843 RHBZ#2389814 RHBZ#2389815");

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~31.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-httpd", rpm:"nextcloud-httpd~31.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-mysql", rpm:"nextcloud-mysql~31.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-nginx", rpm:"nextcloud-nginx~31.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-postgresql", rpm:"nextcloud-postgresql~31.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-sqlite", rpm:"nextcloud-sqlite~31.0.9~1.fc43", rls:"FC43"))) {
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
