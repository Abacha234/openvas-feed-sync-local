# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4092.1");
  script_cve_id("CVE-2025-1352", "CVE-2025-1372", "CVE-2025-1376", "CVE-2025-1377");
  script_tag(name:"creation_date", value:"2025-11-26 04:15:37 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-04 20:19:09 +0000 (Tue, 04 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4092-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254092-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237242");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023341.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the SUSE-SU-2025:4092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for elfutils fixes the following issues:

- Fixing build/testsuite for more recent glibc and kernels.

- Fixing denial of service and general buffer overflow errors
 (bsc#1237236, bsc#1237240, bsc#1237241, bsc#1237242):

 - CVE-2025-1376: Fixed denial of service in function elf_strptr in the library /libelf/elf_strptr.c of the component eu-strip
 - CVE-2025-1377: Fixed denial of service in function gelf_getsymshndx of the file strip.c of the component eu-strip
 - CVE-2025-1372: Fixed buffer overflow in function dump_data_section/print_string_section of the file readelf.c of the component eu-readelf
 - CVE-2025-1352: Fixed SEGV (illegal read access) in function __libdw_thread_tail in the library libdw_alloc.c of the component eu-readelf

- Fixing testsuite race conditions in run-debuginfod-find.sh.");

  script_tag(name:"affected", value:"'elfutils' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"debuginfod-client", rpm:"debuginfod-client~0.185~150400.5.8.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-lang", rpm:"elfutils-lang~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm-devel", rpm:"libasm-devel~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdebuginfod1", rpm:"libdebuginfod1~0.185~150400.5.8.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw-devel", rpm:"libdw-devel~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.185~150400.5.8.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"debuginfod-client", rpm:"debuginfod-client~0.185~150400.5.8.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-lang", rpm:"elfutils-lang~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm-devel", rpm:"libasm-devel~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdebuginfod-devel", rpm:"libdebuginfod-devel~0.185~150400.5.8.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdebuginfod1", rpm:"libdebuginfod1~0.185~150400.5.8.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw-devel", rpm:"libdw-devel~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.185~150400.5.8.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"debuginfod-client", rpm:"debuginfod-client~0.185~150400.5.8.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-lang", rpm:"elfutils-lang~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm-devel", rpm:"libasm-devel~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdebuginfod-devel", rpm:"libdebuginfod-devel~0.185~150400.5.8.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdebuginfod1", rpm:"libdebuginfod1~0.185~150400.5.8.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw-devel", rpm:"libdw-devel~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.185~150400.5.8.3", rls:"SLES15.0SP6"))) {
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
