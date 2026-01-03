# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4534.1");
  script_cve_id("CVE-2025-23259");
  script_tag(name:"creation_date", value:"2026-01-01 04:24:59 +0000 (Thu, 01 Jan 2026)");
  script_version("2026-01-02T15:40:50+0000");
  script_tag(name:"last_modification", value:"2026-01-02 15:40:50 +0000 (Fri, 02 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4534-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4534-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254534-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254161");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023660.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk22' package(s) announced via the SUSE-SU-2025:4534-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dpdk22 fixes the following issues:

Update to version 22.11.10.

Security issues fixed:

- CVE-2025-23259: issue in the Poll Mode Driver (PMD) allows an attacker on a VM in the system to leak information and
 cause a denial of service on the network interface (bsc#1254161).

Other updates and bugfixes:

- Fix SUSE provided DPDK modules tainting the kernel as unsupported (bsc#1214724).");

  script_tag(name:"affected", value:"'dpdk22' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"dpdk22", rpm:"dpdk22~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-devel", rpm:"dpdk22-devel~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-devel-static", rpm:"dpdk22-devel-static~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-doc", rpm:"dpdk22-doc~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-examples", rpm:"dpdk22-examples~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-kmp-default", rpm:"dpdk22-kmp-default~22.11.10_k5.14.21_150500.55.127~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx", rpm:"dpdk22-thunderx~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx-devel", rpm:"dpdk22-thunderx-devel~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx-devel-static", rpm:"dpdk22-thunderx-devel-static~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx-doc", rpm:"dpdk22-thunderx-doc~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx-examples", rpm:"dpdk22-thunderx-examples~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx-kmp-default", rpm:"dpdk22-thunderx-kmp-default~22.11.10_k5.14.21_150500.55.127~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-thunderx-tools", rpm:"dpdk22-thunderx-tools~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk22-tools", rpm:"dpdk22-tools~22.11.10~150500.5.10.1", rls:"openSUSELeap15.6"))) {
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
