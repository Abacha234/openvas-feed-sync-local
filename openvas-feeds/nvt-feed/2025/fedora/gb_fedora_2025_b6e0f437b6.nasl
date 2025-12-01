# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9861010102437986");
  script_cve_id("CVE-2025-61770", "CVE-2025-61771", "CVE-2025-61772", "CVE-2025-61780", "CVE-2025-61919");
  script_tag(name:"creation_date", value:"2025-11-13 04:08:28 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-30 14:24:43 +0000 (Thu, 30 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b6e0f437b6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b6e0f437b6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b6e0f437b6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402174");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402175");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402200");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403126");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403180");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rack' package(s) announced via the FEDORA-2025-b6e0f437b6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to Rack 3.1.19");

  script_tag(name:"affected", value:"'rubygem-rack' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack", rpm:"rubygem-rack~3.1.19~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-doc", rpm:"rubygem-rack-doc~3.1.19~1.fc43", rls:"FC43"))) {
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
