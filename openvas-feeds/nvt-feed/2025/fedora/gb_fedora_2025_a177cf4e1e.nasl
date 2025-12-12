# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.971779910241011101");
  script_cve_id("CVE-2025-63938");
  script_tag(name:"creation_date", value:"2025-12-11 04:17:12 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-a177cf4e1e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a177cf4e1e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a177cf4e1e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417329");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyproxy' package(s) announced via the FEDORA-2025-a177cf4e1e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Add upstream patch to fix CVE-2025-63938.");

  script_tag(name:"affected", value:"'tinyproxy' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"tinyproxy", rpm:"tinyproxy~1.11.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyproxy-debuginfo", rpm:"tinyproxy-debuginfo~1.11.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyproxy-debugsource", rpm:"tinyproxy-debugsource~1.11.2~5.fc42", rls:"FC42"))) {
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
