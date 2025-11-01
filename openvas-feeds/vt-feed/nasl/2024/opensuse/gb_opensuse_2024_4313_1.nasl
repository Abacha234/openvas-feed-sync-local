# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856849");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-48985", "CVE-2022-49006", "CVE-2022-49010", "CVE-2022-49011", "CVE-2022-49019", "CVE-2022-49021", "CVE-2022-49022", "CVE-2022-49029", "CVE-2022-49031", "CVE-2022-49032", "CVE-2023-52524", "CVE-2024-49925", "CVE-2024-50089", "CVE-2024-50115", "CVE-2024-50125", "CVE-2024-50127", "CVE-2024-50154", "CVE-2024-50205", "CVE-2024-50208", "CVE-2024-50264", "CVE-2024-50267", "CVE-2024-50279", "CVE-2024-50290", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53061", "CVE-2024-53063");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 19:42:39 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-12-14 05:05:38 +0000 (Sat, 14 Dec 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:4313-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4313-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PCO2TL4OCZ4YUXTF7OMLI6WH3WKDUC2G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:4313-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2023-52524: Fixed possible corruption in nfc/llcp (bsc#1220927).

  * CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core
      (bsc#1232224)

  * CVE-2024-50089: unicode: Do not special case ignorable code points
      (bsc#1232860).

  * CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory
      (bsc#1232919).

  * CVE-2024-50125: Bluetooth: SCO: Fix UAF on sco_sock_timeout (bsc#1232928).

  * CVE-2024-50127: net: sched: fix use-after-free in taprio_change()
      (bsc#1232907).

  * CVE-2024-50154: tcp/dccp: Do not use timer_pending() in reqsk_queue_unlink()
      (bsc#1233070)

  * CVE-2024-50205: ALSA: firewire-lib: Avoid division by zero in
      apply_constraint_to_size() (bsc#1233293).

  * CVE-2024-50208: RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages
      (bsc#1233117).

  * CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer
      occurring in vsk->trans (bsc#1233453).

  * CVE-2024-50267: USB: serial: io_edgeport: fix use after free in debug printk
      (bsc#1233456).

  * CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when
      resizing (bsc#1233468).

  * CVE-2024-50290: media: cx24116: prevent overflows on SNR calculus
      (bsc#1233479).

  * CVE-2024-50301: security/keys: fix slab-out-of-bounds in key_task_permission
      (bsc#1233490).

  * CVE-2024-50302: HID: core: zero-initialize the report buffer (bsc#1233491).

  * CVE-2024-53061: media: s5p-jpeg: prevent buffer overflows (bsc#1233555).

  * CVE-2024-53063: media: dvbdev: prevent the risk of out of memory access
      (bsc#1233557).

  The following non-security bugs were fixed:

  * Update config files (bsc#1218644).

  * e1000e: Correct NVM checksum verification flow (jsc#SLE-8100).

  * e1000e: Correct NVM checksum verification flow (jsc#SLE-8100).

  * e1000e: Do not take care about recovery NVM checksum (jsc#SLE-8100).

  * e1000e: Do not take care about recovery NVM checksum (jsc#SLE-8100).

  * ena: Remove rcu_read_lock() around XDP program invocation (bsc#1198778).

  * ethernet: amazon: ena: A typo fix in the file ena_com.h (bsc#1198778).

  * initramfs: avoid filename buffer overrun (bsc#1232436).

  * kernel-binary: Enable livepatch package only when livepatch is enabled
      Otherwise the filelist may be empty failing the build (bsc#1218644).

  * net: ena: Add capabilities field with support for ENI stats capability
   ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
