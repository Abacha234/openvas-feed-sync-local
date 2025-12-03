# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0314");
  script_cve_id("CVE-2025-64505", "CVE-2025-64506", "CVE-2025-64720", "CVE-2025-65018");
  script_tag(name:"creation_date", value:"2025-12-02 04:15:04 +0000 (Tue, 02 Dec 2025)");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0314");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0314.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34766");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/11/22/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the MGASA-2025-0314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LIBPNG is vulnerable to a heap buffer overflow in `png_do_quantize` via
malformed palette index. (CVE-2025-64505)
LIBPNG is vulnerable to a heap buffer over-read in
`png_write_image_8bit` with grayscale+alpha or RGB/RGBA images.
(CVE-2025-64506)
LIBPNG is vulnerable to a buffer overflow in `png_image_read_composite`
via incorrect palette premultiplication. (CVE-2025-64720)
 LIBPNG is vulnerable to a heap buffer overflow in `png_combine_row`
triggered via `png_image_finish_read`. (CVE-2025-65018)");

  script_tag(name:"affected", value:"'libpng' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.6.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png16_16", rpm:"lib64png16_16~1.6.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.6.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16_16", rpm:"libpng16_16~1.6.38~1.1.mga9", rls:"MAGEIA9"))) {
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
