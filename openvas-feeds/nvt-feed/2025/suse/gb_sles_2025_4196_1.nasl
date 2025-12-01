# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4196.1");
  script_cve_id("CVE-2025-54770", "CVE-2025-54771", "CVE-2025-61661", "CVE-2025-61662", "CVE-2025-61663", "CVE-2025-61664");
  script_tag(name:"creation_date", value:"2025-11-26 04:15:37 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-18 19:15:50 +0000 (Tue, 18 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4196-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254196-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252935");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023336.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the SUSE-SU-2025:4196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 fixes the following issues:

- CVE-2025-54770: Fixed missing unregister call for net_set_vlan command may lead to use-after-free (bsc#1252930)
- CVE-2025-54771: Fixed rub_file_close() does not properly controls the fs refcount (bsc#1252931)
- CVE-2025-61661: Fixed out-of-bounds write in grub_usb_get_string() function (bsc#1252932)
- CVE-2025-61662: Fixed missing unregister call for gettext command may lead to use-after-free (bsc#1252933)
- CVE-2025-61663: Fixed missing unregister call for normal commands may lead to use-after-free (bsc#1252934)
- CVE-2025-61664: Fixed missing unregister call for normal_exit command may lead to use-after-free (bsc#1252935)

Other fixes:

- Bump upstream SBAT generation to 6
- Fix timeout when loading initrd via http after PPC CAS reboot (bsc#1245953)
- Fix PPC CAS reboot failure work when initiated via submenu (bsc#1241132)
- Fix out of memory issue on PowerPC by increasing RMA size (bsc#1236744, bsc#1252269)");

  script_tag(name:"affected", value:"'grub2' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-arm64-efi", rpm:"grub2-arm64-efi~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-pc", rpm:"grub2-i386-pc~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-powerpc-ieee1275", rpm:"grub2-powerpc-ieee1275~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-s390x-emu", rpm:"grub2-s390x-emu~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-snapper-plugin", rpm:"grub2-snapper-plugin~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-systemd-sleep-plugin", rpm:"grub2-systemd-sleep-plugin~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.12~150600.8.44.2", rls:"SLES15.0SP6"))) {
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
