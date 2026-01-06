# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9910210098909852100");
  script_cve_id("CVE-2024-25621", "CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723");
  script_tag(name:"creation_date", value:"2026-01-05 04:31:55 +0000 (Mon, 05 Jan 2026)");
  script_version("2026-01-05T05:51:45+0000");
  script_tag(name:"last_modification", value:"2026-01-05 05:51:45 +0000 (Mon, 05 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-31 02:29:30 +0000 (Wed, 31 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-cfdb90b52d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-cfdb90b52d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-cfdb90b52d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398680");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399357");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407883");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409352");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410302");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412383");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412764");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419006");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'doctl' package(s) announced via the FEDORA-2025-cfdb90b52d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.148.0");

  script_tag(name:"affected", value:"'doctl' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"doctl", rpm:"doctl~1.148.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"doctl-debuginfo", rpm:"doctl-debuginfo~1.148.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"doctl-debugsource", rpm:"doctl-debugsource~1.148.0~1.fc42", rls:"FC42"))) {
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
