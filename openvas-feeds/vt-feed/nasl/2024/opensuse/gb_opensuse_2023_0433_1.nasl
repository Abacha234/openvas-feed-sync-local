# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833677");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-24588", "CVE-2022-4382", "CVE-2022-47929", "CVE-2023-0122", "CVE-2023-0179", "CVE-2023-0266", "CVE-2023-0590", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:38 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:49 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:0433-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0433-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DYJKA4HISSSYZNHBGUEPII5Q7FNAJTIG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:0433-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various
     security and bugfixes.


     The following security bugs were fixed:

  - CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in
       net/sched/sch_atm.c because of type confusion (non-negative numbers can
       sometimes indicate a TC_ACT_SHOT condition rather than valid
       classification results) (bsc#1207125).

  - CVE-2023-23454: Fixed denial or service in cbq_classify in
       net/sched/sch_cbq.c (bnc#1207036).

  - CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).

  - CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM
       package. SNDRV_CTL_IOCTL_ELEM_{READWRITE}32 was missing locks that
       could have been used in a use-after-free that could have resulted in a
       privilege escalation to gain ring0 access from the system user
       (bsc#1207134).

  - CVE-2023-0179: Fixed incorrect arithmetic when fetching VLAN header
       bits (bsc#1207034).

  - CVE-2023-0122: Fixed a NULL pointer dereference vulnerability in
       nvmet_setup_auth(), that allowed an attacker to perform a Pre-Auth
       Denial of Service (DoS) attack on a remote machine (bnc#1207050).

  - CVE-2022-4382: Fixed a use-after-free flaw that was caused by a race
       condition among the superblock operations inside the gadgetfs code
       (bsc#1206258).

  - CVE-2020-24588: Fixed injection of arbitrary network packets against
       devices that support receiving non-SSP A-MSDU frames (which is mandatory
       as part of 802.11n) (bsc#1199701).

     The following non-security bugs were fixed:

  - ACPI: EC: Fix EC address space handler unregistration (bsc#1207149).

  - ACPI: EC: Fix ECDT probe ordering issues (bsc#1207149).

  - ACPI: PRM: Check whether EFI runtime is available (git-fixes).

  - ACPICA: Allow address_space_handler Install and _REG execution as 2
       separate steps (bsc#1207149).

  - ACPICA: include/acpi/acpixf.h: Fix indentation (bsc#1207149).

  - ALSA: control-led: use strscpy in set_led_id() (git-fixes).

  - ALSA: hda - Enable headset mic on another Dell laptop with ALC3254
       (git-fixes).

  - ALSA: hda/hdmi: Add a HP device 0x8715 to force connect list (git-fixes).

  - ALSA: hda/realtek - Turn on power early (git-fixes).

  - ALSA: hda/realtek: Add Acer Predator PH315-54 (git-fixes).

  - ALSA: hda/realtek: Enable mute/micmute LEDs on HP Spectre x360 13-aw0xxx
       (git-fixes).

  - ALSA: hda/realtek: fix mute/micmute LEDs do not work for a HP plat ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
