# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0276");
  script_cve_id("CVE-2023-31484", "CVE-2023-31486");
  script_tag(name:"creation_date", value:"2025-11-13 04:11:10 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-08 17:06:34 +0000 (Mon, 08 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2025-0276)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0276");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0276.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31852");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/04/29/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-CPAN, perl-HTTP-Tiny' package(s) announced via the MGASA-2025-0276 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CPAN.pm before 2.35 does not verify TLS certificates when downloading
distributions over HTTPS. (CVE-2023-31484)
HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available
standalone on CPAN, has an insecure default TLS configuration where
users must opt in to verify certificates. (CVE-2023-31486)");

  script_tag(name:"affected", value:"'perl-CPAN, perl-HTTP-Tiny' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~2.340.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-Tiny", rpm:"perl-HTTP-Tiny~0.82.0~1.1.mga9", rls:"MAGEIA9"))) {
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
