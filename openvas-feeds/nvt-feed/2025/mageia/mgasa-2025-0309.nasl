# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0309");
  script_cve_id("CVE-2025-39869", "CVE-2025-39870", "CVE-2025-39871", "CVE-2025-39873", "CVE-2025-39876", "CVE-2025-39877", "CVE-2025-39880", "CVE-2025-39881", "CVE-2025-39882", "CVE-2025-39883", "CVE-2025-39885", "CVE-2025-39886", "CVE-2025-39907", "CVE-2025-39909", "CVE-2025-39911", "CVE-2025-39913", "CVE-2025-39914", "CVE-2025-39916", "CVE-2025-39923", "CVE-2025-39929", "CVE-2025-39931", "CVE-2025-39934", "CVE-2025-39937", "CVE-2025-39938", "CVE-2025-39942", "CVE-2025-39943", "CVE-2025-39944", "CVE-2025-39945", "CVE-2025-39946", "CVE-2025-39947", "CVE-2025-39949", "CVE-2025-39951", "CVE-2025-39952", "CVE-2025-39953", "CVE-2025-39955", "CVE-2025-39957", "CVE-2025-39961", "CVE-2025-39964", "CVE-2025-39965", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39975", "CVE-2025-39977", "CVE-2025-39978", "CVE-2025-39980", "CVE-2025-39982", "CVE-2025-39985", "CVE-2025-39986", "CVE-2025-39987", "CVE-2025-39988", "CVE-2025-39993", "CVE-2025-39994", "CVE-2025-39995", "CVE-2025-39996", "CVE-2025-39998", "CVE-2025-40006", "CVE-2025-40008", "CVE-2025-40010", "CVE-2025-40011", "CVE-2025-40013", "CVE-2025-40016", "CVE-2025-40018", "CVE-2025-40019", "CVE-2025-40020", "CVE-2025-40021", "CVE-2025-40022", "CVE-2025-40024", "CVE-2025-40026", "CVE-2025-40027", "CVE-2025-40029", "CVE-2025-40030", "CVE-2025-40032", "CVE-2025-40033", "CVE-2025-40035", "CVE-2025-40036", "CVE-2025-40038", "CVE-2025-40040", "CVE-2025-40042", "CVE-2025-40043", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40049", "CVE-2025-40051", "CVE-2025-40052", "CVE-2025-40053", "CVE-2025-40055", "CVE-2025-40056", "CVE-2025-40060", "CVE-2025-40061", "CVE-2025-40062", "CVE-2025-40067", "CVE-2025-40068", "CVE-2025-40070", "CVE-2025-40071", "CVE-2025-40078", "CVE-2025-40080", "CVE-2025-40081", "CVE-2025-40084", "CVE-2025-40085", "CVE-2025-40087", "CVE-2025-40088", "CVE-2025-40092", "CVE-2025-40093", "CVE-2025-40094", "CVE-2025-40095", "CVE-2025-40096", "CVE-2025-40099", "CVE-2025-40100", "CVE-2025-40103", "CVE-2025-40104", "CVE-2025-40105", "CVE-2025-40106", "CVE-2025-40107", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-11-24 04:18:19 +0000 (Mon, 24 Nov 2025)");
  script_version("2025-11-24T05:41:47+0000");
  script_tag(name:"last_modification", value:"2025-11-24 05:41:47 +0000 (Mon, 24 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0309");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0309.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34713");
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

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2025-0309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upstream kernel version 6.6.116 fixes bugs and vulnerabilities.
The kmod-virtualbox & kmod-xtables-addons packages have been updated to
work with this new kernel.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586", rpm:"kernel-desktop586~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel", rpm:"kernel-desktop586-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server", rpm:"kernel-server~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel", rpm:"kernel-server-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.1.14~13.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.24~87.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf1", rpm:"lib64bpf1~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf1", rpm:"libbpf1~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.6.116~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-6.6.116-desktop-1.mga9", rpm:"virtualbox-kernel-6.6.116-desktop-1.mga9~7.1.14~13.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-6.6.116-server-1.mga9", rpm:"virtualbox-kernel-6.6.116-server-1.mga9~7.1.14~13.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.1.14~13.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.1.14~13.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.116-desktop-1.mga9", rpm:"xtables-addons-kernel-6.6.116-desktop-1.mga9~3.24~87.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.116-desktop586-1.mga9", rpm:"xtables-addons-kernel-6.6.116-desktop586-1.mga9~3.24~87.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.116-server-1.mga9", rpm:"xtables-addons-kernel-6.6.116-server-1.mga9~3.24~87.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.24~87.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.24~87.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.24~87.mga9", rls:"MAGEIA9"))) {
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
