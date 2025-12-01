# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0284");
  script_cve_id("CVE-2025-40929");
  script_tag(name:"creation_date", value:"2025-11-14 04:09:58 +0000 (Fri, 14 Nov 2025)");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0284)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0284");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0284.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34627");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/09/08/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Cpanel-JSON-XS' package(s) announced via the MGASA-2025-0284 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cpanel::JSON::XS before version 4.40 for Perl has an integer buffer
overflow causing a segfault when parsing crafted JSON, enabling
denial-of-service attacks or other unspecified impact. (CVE-2025-40929)");

  script_tag(name:"affected", value:"'perl-Cpanel-JSON-XS' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Cpanel-JSON-XS", rpm:"perl-Cpanel-JSON-XS~4.350.0~1.1.mga9", rls:"MAGEIA9"))) {
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
