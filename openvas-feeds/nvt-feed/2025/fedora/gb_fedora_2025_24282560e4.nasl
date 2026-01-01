# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.242825601014");
  script_cve_id("CVE-2025-55753");
  script_tag(name:"creation_date", value:"2025-12-17 10:50:36 +0000 (Wed, 17 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-24282560e4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-24282560e4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-24282560e4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420213");
  script_xref(name:"URL", value:"https://github.com/icing/mod_md/releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_md' package(s) announced via the FEDORA-2025-24282560e4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update includes the latest upstream release of `mod_md`, with various bug fixes and enhancements. See [link moved to references] for more information.

A fix for the security vulnerability `CVE-2025-55753` is also included.");

  script_tag(name:"affected", value:"'mod_md' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"mod_md", rpm:"mod_md~2.6.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_md-debuginfo", rpm:"mod_md-debuginfo~2.6.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_md-debugsource", rpm:"mod_md-debugsource~2.6.7~1.fc43", rls:"FC43"))) {
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
