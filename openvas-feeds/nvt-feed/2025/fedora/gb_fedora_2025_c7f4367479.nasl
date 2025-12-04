# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9971024367479");
  script_cve_id("CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725", "CVE-2025-64761");
  script_tag(name:"creation_date", value:"2025-12-03 04:12:06 +0000 (Wed, 03 Dec 2025)");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-01 15:44:38 +0000 (Mon, 01 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-c7f4367479)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c7f4367479");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c7f4367479");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408334");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408737");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409807");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410757");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411653");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417146");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openbao' package(s) announced via the FEDORA-2025-c7f4367479 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to upstream 2.4.4, fixing CVE-2025-64761.

----

Adds hsm tag.

The fedora-43 build was done with golang-1.25.4 which fixed CVE-2025-58189, CVE-2025-58188, CVE-2025-61725, CVE-2025-61723, CVE-2025-58185, and CVE-2025-58183.");

  script_tag(name:"affected", value:"'openbao' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"openbao", rpm:"openbao~2.4.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openbao-debuginfo", rpm:"openbao-debuginfo~2.4.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openbao-debugsource", rpm:"openbao-debugsource~2.4.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openbao-vault-compat", rpm:"openbao-vault-compat~2.4.4~1.fc43", rls:"FC43"))) {
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
