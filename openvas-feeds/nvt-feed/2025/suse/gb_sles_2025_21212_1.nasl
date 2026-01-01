# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21212.1");
  script_cve_id("CVE-2024-56738", "CVE-2025-54770", "CVE-2025-54771", "CVE-2025-61661", "CVE-2025-61662", "CVE-2025-61663", "CVE-2025-61664");
  script_tag(name:"creation_date", value:"2025-12-19 15:00:01 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-18 19:15:50 +0000 (Tue, 18 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21212-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521212-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252935");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023596.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the SUSE-SU-2025:21212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 fixes the following issues:

Changes in grub2:

- CVE-2025-54771: Fixed grub_file_close() does not properly controls the fs refcount (bsc#1252931)
- CVE-2025-54770: Fixed missing unregister call for net_set_vlan command may lead to use-after-free (bsc#1252930)
- CVE-2025-61662: Fixed missing unregister call for gettext command may lead to use-after-free (bsc#1252933)
- CVE-2025-61663: Fixed missing unregister call for normal commands may lead to use-after-free (bsc#1252934)
- CVE-2025-61664: Fixed missing unregister call for normal_exit command may lead to use-after-free (bsc#1252935)
- CVE-2025-61661: Fixed out-of-bounds write in grub_usb_get_string() function (bsc#1252932)

- Bump upstream SBAT generation to 6

- Fix 'sparse file not allowed' error after grub2-reboot (bsc#1245738)
- Fix PowerPC network boot prefix to correctly locate grub.cfg (bsc#1249385)
- turn off page flipping for i386-pc using VBE video backend (bsc#1245636)
- Fix boot hangs in setting up serial console when ACPI SPCR table is present
 and redirection is disabled (bsc#1249088)
- Fix timeout when loading initrd via http after PPC CAS reboot (bsc#1245953)
- Skip mount point in grub_find_device function (bsc#1246231)

- CVE-2024-56738: Fixed side-channel attack due to not constant-time algorithm in grub_crypto_memcmp (bsc#1234959)");

  script_tag(name:"affected", value:"'grub2' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-arm64-efi", rpm:"grub2-arm64-efi~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-pc", rpm:"grub2-i386-pc~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-powerpc-ieee1275", rpm:"grub2-powerpc-ieee1275~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-s390x-emu", rpm:"grub2-s390x-emu~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-snapper-plugin", rpm:"grub2-snapper-plugin~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-systemd-sleep-plugin", rpm:"grub2-systemd-sleep-plugin~2.12~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.12~160000.3.1", rls:"SLES16.0.0"))) {
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
