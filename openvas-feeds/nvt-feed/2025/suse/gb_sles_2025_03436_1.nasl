# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03436.1");
  script_cve_id("CVE-2025-41244");
  script_tag(name:"creation_date", value:"2025-10-02 04:13:26 +0000 (Thu, 02 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03436-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03436-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503436-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250373");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041977.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools' package(s) announced via the SUSE-SU-2025:03436-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools fixes the following issues:

- CVE-2025-41244: local privilege escalation via the Service Discovery Plugin (bsc#1250373).");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~13.0.0~4.89.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~13.0.0~4.89.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~13.0.0~4.89.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~13.0.0~4.89.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~13.0.0~4.89.1", rls:"SLES12.0SP5"))) {
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
