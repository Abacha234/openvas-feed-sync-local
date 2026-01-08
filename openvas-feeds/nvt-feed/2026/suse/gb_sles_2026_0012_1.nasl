# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0012.1");
  script_cve_id("CVE-2025-27466", "CVE-2025-58142", "CVE-2025-58143", "CVE-2025-58147", "CVE-2025-58148", "CVE-2025-58149");
  script_tag(name:"creation_date", value:"2026-01-06 15:16:17 +0000 (Tue, 06 Jan 2026)");
  script_version("2026-01-07T05:47:44+0000");
  script_tag(name:"last_modification", value:"2026-01-07 05:47:44 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0012-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260012-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254180");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023676.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2026:0012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security issues fixed:

- CVE-2025-27466: NULL pointer dereference in the Viridian interface when updating the reference TSC area (bsc#1248807).
- CVE-2025-58142: NULL pointer dereference in the Viridian interface due to assumption that the SIM page is mapped when
 a synthetic timer message has to be delivered (bsc#1248807).
- CVE-2025-58143: information leak and reference counter underflow in the Viridian interface due to race in the mapping
 of the reference TSC page (bsc#1248807).
- CVE-2025-58147: incorrect input sanitisation in Viridian hypercalls using the HV_VP_SET Sparse format can lead to
 out-of-bounds write through `vpmask_set()` (bsc#1251271).
- CVE-2025-58148: incorrect input sanitisation in Viridian hypercalls using any input format can lead to out-of-bounds
 read through `send_ipi()` (bsc#1251271).
- CVE-2025-58149: incorrect removal of permissions on PCI device unplug allows PV guests to access memory of devices no
 longer assigned to them (bsc#1252692).

Other issues fixed:

- Several upstream bug fixes (bsc#1027519).
- Failure to restart xenstored (bsc#1254180).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.18.5_08~150600.3.34.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.18.5_08~150600.3.34.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.18.5_08~150600.3.34.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.18.5_08~150600.3.34.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.18.5_08~150600.3.34.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-xendomains-wait-disk", rpm:"xen-tools-xendomains-wait-disk~4.18.5_08~150600.3.34.2", rls:"SLES15.0SP6"))) {
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
