# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1981989870897102");
  script_cve_id("CVE-2025-59940");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-1b1bb708af)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-1b1bb708af");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-1b1bb708af");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2344045");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400372");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400521");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-mkdocs-include-markdown-plugin' package(s) announced via the FEDORA-2025-1b1bb708af advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# v7.2.0
## New features

- Add new argument `order` to sort multiple inclusions.

# v7.1.8
## Bug fixes

- Escape substitution placeholders to prevent malformed output in edge cases. (CVE-2025-59940)");

  script_tag(name:"affected", value:"'python-mkdocs-include-markdown-plugin' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-mkdocs-include-markdown-plugin", rpm:"python-mkdocs-include-markdown-plugin~7.2.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mkdocs-include-markdown-plugin+cache", rpm:"python3-mkdocs-include-markdown-plugin+cache~7.2.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mkdocs-include-markdown-plugin", rpm:"python3-mkdocs-include-markdown-plugin~7.2.0~1.fc43", rls:"FC43"))) {
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
