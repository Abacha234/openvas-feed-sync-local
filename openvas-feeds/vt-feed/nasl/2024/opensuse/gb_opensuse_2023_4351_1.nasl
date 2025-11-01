# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833511");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-2163", "CVE-2023-31085", "CVE-2023-34324", "CVE-2023-3777", "CVE-2023-39189", "CVE-2023-45862", "CVE-2023-46813", "CVE-2023-5178");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 15:10:41 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:49:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:4351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4351-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UAYQAYJCQOCWO3FEBKOXFSRRIBVRZ3VV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:4351-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security and bugfixes.

  The following security bugs were fixed:

  * CVE-2023-3777: Fixed a use-after-free vulnerability in netfilter: nf_tables
      component can be exploited to achieve local privilege escalation.
      (bsc#1215095)

  * CVE-2023-46813: Fixed a local privilege escalation with user-space programs
      that have access to MMIO regions (bsc#1212649).

  * CVE-2023-31085: Fixed a divide-by-zero error in do_div(sz, mtd- erasesize)
      that could cause a local DoS. (bsc#1210778)

  * CVE-2023-45862: Fixed an issue in the ENE UB6250 reader driver whwere an
      object could potentially extend beyond the end of an allocation causing.
      (bsc#1216051)

  * CVE-2023-5178: Fixed an UAF in queue initialization setup. (bsc#1215768)

  * CVE-2023-2163: Fixed an incorrect verifier pruning in BPF that could lead to
      unsafe code paths being incorrectly marked as safe, resulting in arbitrary
      read/write in kernel memory, lateral privilege escalation, and container
      escape. (bsc#1215518)

  * CVE-2023-34324: Fixed a possible deadlock in Linux kernel event handling.
      (bsc#1215745).

  * CVE-2023-39189: Fixed a flaw in the Netfilter subsystem that could allow a
      local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read,
      leading to a crash or information disclosure. (bsc#1216046)

  The following non-security bugs were fixed:

  * 9p: virtio: make sure 'offs' is initialized in zc_request (git-fixes).

  * ACPI: irq: Fix incorrect return value in acpi_register_gsi() (git-fixes).

  * ACPI: resource: Skip IRQ override on ASUS ExpertBook B1402CBA (git-fixes).

  * ALSA: hda/realtek: Change model for Intel RVP board (git-fixes).

  * ALSA: hda: Disable power save for solving pop issue on Lenovo ThinkCentre
      M70q (git-fixes).

  * ALSA: usb-audio: Fix microphone sound on Opencomm2 Headset (git-fixes).

  * ASoC: codecs: wcd938x-sdw: fix runtime PM imbalance on probe errors (git-
      fixes).

  * ASoC: codecs: wcd938x-sdw: fix use after free on driver unbind (git-fixes).

  * ASoC: codecs: wcd938x: drop bogus bind error handling (git-fixes).

  * ASoC: codecs: wcd938x: fix unbind tear down order (git-fixes).

  * ASoC: fsl: imx-pcm-rpmsg: Add SNDRV_PCM_INFO_BATCH flag (git-fixes).

  * ASoC: imx-rpmsg: Set ignore_pmdown_time for dai_link (git-fixes).

  * ASoC: pxa: fix a memory leak in probe() (git-fixes).

  * Bluetooth: Avoid redundant authentication (git-fixes).

  * ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
