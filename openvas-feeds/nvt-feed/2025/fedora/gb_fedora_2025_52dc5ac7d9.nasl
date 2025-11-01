# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.52100995979971009");
  script_cve_id("CVE-2025-11687");
  script_tag(name:"creation_date", value:"2025-10-21 04:05:41 +0000 (Tue, 21 Oct 2025)");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-52dc5ac7d9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-52dc5ac7d9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-52dc5ac7d9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403282");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403539");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gi-docgen' package(s) announced via the FEDORA-2025-52dc5ac7d9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## gi-docgen 2025.5 - 2025-10-11

This is a security fix for CVE-2025-11687. 'The severity of this issue depends on what else is hosted on the same domain as the docs. XSS on a website that hosts only gi-docgen docs and nothing else is likely harmless.'

Fixed
-----

- Make sure to escape query strings");

  script_tag(name:"affected", value:"'gi-docgen' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"gi-docgen", rpm:"gi-docgen~2025.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gi-docgen-doc", rpm:"gi-docgen-doc~2025.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gi-docgen-fonts", rpm:"gi-docgen-fonts~2025.5~1.fc41", rls:"FC41"))) {
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
