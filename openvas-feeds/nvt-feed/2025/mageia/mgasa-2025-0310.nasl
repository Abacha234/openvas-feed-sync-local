# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0310");
  script_cve_id("CVE-2025-39869", "CVE-2025-39870", "CVE-2025-39871", "CVE-2025-39873", "CVE-2025-39876", "CVE-2025-39877", "CVE-2025-39880", "CVE-2025-39881", "CVE-2025-39882", "CVE-2025-39883", "CVE-2025-39885", "CVE-2025-39886", "CVE-2025-39907", "CVE-2025-39909", "CVE-2025-39911", "CVE-2025-39913", "CVE-2025-39914", "CVE-2025-39916", "CVE-2025-39923", "CVE-2025-39929", "CVE-2025-39931", "CVE-2025-39934", "CVE-2025-39937", "CVE-2025-39938", "CVE-2025-39942", "CVE-2025-39943", "CVE-2025-39944", "CVE-2025-39945", "CVE-2025-39946", "CVE-2025-39947", "CVE-2025-39949", "CVE-2025-39951", "CVE-2025-39952", "CVE-2025-39953", "CVE-2025-39955", "CVE-2025-39957", "CVE-2025-39961", "CVE-2025-39964", "CVE-2025-39965", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39975", "CVE-2025-39977", "CVE-2025-39978", "CVE-2025-39980", "CVE-2025-39982", "CVE-2025-39985", "CVE-2025-39986", "CVE-2025-39987", "CVE-2025-39988", "CVE-2025-39993", "CVE-2025-39994", "CVE-2025-39995", "CVE-2025-39996", "CVE-2025-39998", "CVE-2025-40006", "CVE-2025-40008", "CVE-2025-40010", "CVE-2025-40011", "CVE-2025-40013", "CVE-2025-40016", "CVE-2025-40018", "CVE-2025-40019", "CVE-2025-40020", "CVE-2025-40021", "CVE-2025-40022", "CVE-2025-40024", "CVE-2025-40026", "CVE-2025-40027", "CVE-2025-40029", "CVE-2025-40030", "CVE-2025-40032", "CVE-2025-40033", "CVE-2025-40035", "CVE-2025-40036", "CVE-2025-40038", "CVE-2025-40040", "CVE-2025-40042", "CVE-2025-40043", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40049", "CVE-2025-40051", "CVE-2025-40052", "CVE-2025-40053", "CVE-2025-40055", "CVE-2025-40056", "CVE-2025-40060", "CVE-2025-40061", "CVE-2025-40062", "CVE-2025-40067", "CVE-2025-40068", "CVE-2025-40070", "CVE-2025-40071", "CVE-2025-40078", "CVE-2025-40080", "CVE-2025-40081", "CVE-2025-40084", "CVE-2025-40085", "CVE-2025-40087", "CVE-2025-40088", "CVE-2025-40092", "CVE-2025-40093", "CVE-2025-40094", "CVE-2025-40095", "CVE-2025-40096", "CVE-2025-40099", "CVE-2025-40100", "CVE-2025-40103", "CVE-2025-40104", "CVE-2025-40105", "CVE-2025-40106", "CVE-2025-40107", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-11-24 04:18:19 +0000 (Mon, 24 Nov 2025)");
  script_version("2025-11-24T05:41:47+0000");
  script_tag(name:"last_modification", value:"2025-11-24 05:41:47 +0000 (Mon, 24 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0310");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0310.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34721");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.106");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.107");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.108");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.109");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.110");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.111");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.112");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.113");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.114");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.115");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.116");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2025-0310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vanilla upstream kernel version 6.6.116 fixes bugs and vulnerabilities.
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.6.116~1.mga9", rls:"MAGEIA9"))) {
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
