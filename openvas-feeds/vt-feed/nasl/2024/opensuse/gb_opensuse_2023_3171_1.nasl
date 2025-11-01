# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833541");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-20593", "CVE-2023-2985", "CVE-2023-3117", "CVE-2023-31248", "CVE-2023-3390", "CVE-2023-35001", "CVE-2023-3812");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 15:09:10 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:37:58 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:3171-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3171-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TYDJJIJMALRQY2YMTGB2KCDBW4PIRYS2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:3171-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security
  and bugfixes.

  The following security bugs were fixed:

  * CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in
      fs/hfsplus/super.c that could allow a local user to cause a denial of
      service (bsc#1211867).

  * CVE-2023-3117: Fixed an use-after-free vulnerability in the netfilter
      subsystem when processing named and anonymous sets in batch requests that
      could allow a local user with CAP_NET_ADMIN capability to crash or
      potentially escalate their privileges on the system (bsc#1213245).

  * CVE-2023-3390: Fixed an use-after-free vulnerability in the netfilter
      subsystem in net/netfilter/nf_tables_api.c that could allow a local attacker
      with user access to cause a privilege escalation issue (bsc#1212846).

  * CVE-2023-3812: Fixed an out-of-bounds memory access flaw in the TUN/TAP
      device driver functionality that could allow a local user to crash or
      potentially escalate their privileges on the system (bsc#1213543).

  * CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an
      attacker to potentially access sensitive information (bsc#1213286).

  * CVE-2023-31248: Fixed an use-after-free vulnerability in
      nft_chain_lookup_byid that could allow a local attacker to escalate their
      privilege (bsc#1213061).

  * CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder
      that could allow a local attacker to escalate their privilege (bsc#1213059).

  The following non-security bugs were fixed:

  * ACPI: utils: Fix acpi_evaluate_dsm_typed() redefinition error (git-fixes).

  * ALSA: fireface: make read-only const array for model names static (git-
      fixes).

  * ALSA: hda/realtek - remove 3k pull low procedure (git-fixes).

  * ALSA: hda/realtek: Add quirk for ASUS ROG G614Jx (git-fixes).

  * ALSA: hda/realtek: Add quirk for ASUS ROG GA402X (git-fixes).

  * ALSA: hda/realtek: Add quirk for ASUS ROG GX650P (git-fixes).

  * ALSA: hda/realtek: Add quirk for ASUS ROG GZ301V (git-fixes).

  * ALSA: hda/realtek: Add quirk for Clevo NPx0SNx (git-fixes).

  * ALSA: hda/realtek: Add quirk for Clevo NS70AU (git-fixes).

  * ALSA: hda/realtek: Add quirks for Unis H3C Desktop B760 &amp  Q760 (git-fixes).

  * ALSA: hda/realtek: Add support for DELL Oasis 13/14/16 laptops (git-fixes).

  * ALSA: hda/realtek: Amend G634 quirk to enable rear speakers (git-fixes).

  * ALSA: hda/realtek: Enable Mute LED on HP ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
