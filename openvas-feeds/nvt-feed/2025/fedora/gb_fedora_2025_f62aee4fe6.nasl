# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.102629710110141021016");
  script_cve_id("CVE-2025-64500");
  script_tag(name:"creation_date", value:"2025-12-03 04:12:06 +0000 (Wed, 03 Dec 2025)");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-f62aee4fe6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f62aee4fe6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f62aee4fe6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2415750");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2415751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2415752");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2415753");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2416087");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud' package(s) announced via the FEDORA-2025-f62aee4fe6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"32.0.2 release RHBZ#2416087 RHBZ#2415750 RHBZ#2415751 RHBZ#2415752 RHBZ#2415753");

  script_tag(name:"affected", value:"'nextcloud' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~32.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-httpd", rpm:"nextcloud-httpd~32.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-mysql", rpm:"nextcloud-mysql~32.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-nginx", rpm:"nextcloud-nginx~32.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-postgresql", rpm:"nextcloud-postgresql~32.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-sqlite", rpm:"nextcloud-sqlite~32.0.2~1.fc42", rls:"FC42"))) {
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
