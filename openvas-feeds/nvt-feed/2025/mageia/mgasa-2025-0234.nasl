# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0234");
  script_cve_id("CVE-2025-38501", "CVE-2025-38553", "CVE-2025-38555", "CVE-2025-38560", "CVE-2025-38561", "CVE-2025-38562", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38566", "CVE-2025-38568", "CVE-2025-38569", "CVE-2025-38571", "CVE-2025-38572", "CVE-2025-38574", "CVE-2025-38576", "CVE-2025-38577", "CVE-2025-38578", "CVE-2025-38579", "CVE-2025-38581", "CVE-2025-38583", "CVE-2025-38587", "CVE-2025-38588", "CVE-2025-38590", "CVE-2025-38601", "CVE-2025-38602", "CVE-2025-38604", "CVE-2025-38608", "CVE-2025-38609", "CVE-2025-38610", "CVE-2025-38611", "CVE-2025-38612", "CVE-2025-38615", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38622", "CVE-2025-38623", "CVE-2025-38624", "CVE-2025-38625", "CVE-2025-38626", "CVE-2025-38630", "CVE-2025-38632", "CVE-2025-38634", "CVE-2025-38635", "CVE-2025-38639", "CVE-2025-38640", "CVE-2025-38644", "CVE-2025-38645", "CVE-2025-38646", "CVE-2025-38648", "CVE-2025-38650", "CVE-2025-38652", "CVE-2025-38653", "CVE-2025-38656", "CVE-2025-38659", "CVE-2025-38677", "CVE-2025-38679", "CVE-2025-38680", "CVE-2025-38681", "CVE-2025-38683", "CVE-2025-38684", "CVE-2025-38685", "CVE-2025-38687", "CVE-2025-38688", "CVE-2025-38691", "CVE-2025-38692", "CVE-2025-38693", "CVE-2025-38694", "CVE-2025-38695", "CVE-2025-38696", "CVE-2025-38697", "CVE-2025-38698", "CVE-2025-38699", "CVE-2025-38700", "CVE-2025-38701", "CVE-2025-38702", "CVE-2025-38706", "CVE-2025-38707", "CVE-2025-38708", "CVE-2025-38709", "CVE-2025-38711", "CVE-2025-38712", "CVE-2025-38713", "CVE-2025-38714", "CVE-2025-38715", "CVE-2025-38716", "CVE-2025-38718", "CVE-2025-38721", "CVE-2025-38723", "CVE-2025-38724", "CVE-2025-38725", "CVE-2025-38727", "CVE-2025-38728", "CVE-2025-38729", "CVE-2025-38730", "CVE-2025-38732", "CVE-2025-38734", "CVE-2025-38735", "CVE-2025-39673", "CVE-2025-39675", "CVE-2025-39676", "CVE-2025-39679", "CVE-2025-39681", "CVE-2025-39682", "CVE-2025-39683", "CVE-2025-39684", "CVE-2025-39685", "CVE-2025-39686", "CVE-2025-39687", "CVE-2025-39689", "CVE-2025-39691", "CVE-2025-39692", "CVE-2025-39693", "CVE-2025-39694", "CVE-2025-39701", "CVE-2025-39702", "CVE-2025-39703", "CVE-2025-39706", "CVE-2025-39709", "CVE-2025-39710", "CVE-2025-39711", "CVE-2025-39713", "CVE-2025-39714", "CVE-2025-39715", "CVE-2025-39716", "CVE-2025-39718", "CVE-2025-39719", "CVE-2025-39720", "CVE-2025-39721", "CVE-2025-39724", "CVE-2025-39730", "CVE-2025-39731", "CVE-2025-39734");
  script_tag(name:"creation_date", value:"2025-10-10 04:08:17 +0000 (Fri, 10 Oct 2025)");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0234)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0234");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0234.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34595");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.102");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.103");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.104");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.105");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2025-0234 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vanilla upstream kernel version 6.6.105 fixes bugs and vulnerabilities.
For information about the vulnerabilities see the links.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.6.105~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.6.105~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.6.105~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.6.105~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.6.105~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.6.105~1.mga9", rls:"MAGEIA9"))) {
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
