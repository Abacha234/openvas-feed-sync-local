# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856085");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-46925", "CVE-2021-46926", "CVE-2021-46927", "CVE-2021-46929", "CVE-2021-46930", "CVE-2021-46931", "CVE-2021-46933", "CVE-2021-46936", "CVE-2021-47082", "CVE-2021-47087", "CVE-2021-47091", "CVE-2021-47093", "CVE-2021-47094", "CVE-2021-47095", "CVE-2021-47096", "CVE-2021-47097", "CVE-2021-47098", "CVE-2021-47099", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47102", "CVE-2021-47104", "CVE-2021-47105", "CVE-2021-47107", "CVE-2021-47108", "CVE-2022-20154", "CVE-2022-4744", "CVE-2022-48626", "CVE-2022-48629", "CVE-2022-48630", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-52447", "CVE-2023-52450", "CVE-2023-52454", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52477", "CVE-2023-52492", "CVE-2023-52497", "CVE-2023-52501", "CVE-2023-52502", "CVE-2023-52504", "CVE-2023-52507", "CVE-2023-52508", "CVE-2023-52509", "CVE-2023-52510", "CVE-2023-52511", "CVE-2023-52513", "CVE-2023-52515", "CVE-2023-52517", "CVE-2023-52519", "CVE-2023-52520", "CVE-2023-52523", "CVE-2023-52524", "CVE-2023-52525", "CVE-2023-52528", "CVE-2023-52529", "CVE-2023-52532", "CVE-2023-52564", "CVE-2023-52566", "CVE-2023-52567", "CVE-2023-52569", "CVE-2023-52574", "CVE-2023-52575", "CVE-2023-52576", "CVE-2023-52582", "CVE-2023-52583", "CVE-2023-52597", "CVE-2023-52605", "CVE-2023-52621", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2024-25742", "CVE-2024-26600");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-17 17:15:54 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-19 01:04:15 +0000 (Fri, 19 Apr 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:1321-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1321-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BDCQEOHS2VSXCSQWYSL6KIQHBTBHSLT5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:1321-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-25742: Fixed insufficient validation during #VC instruction
      emulation in x86/sev (bsc#1221725).

  * CVE-2023-52519: Fixed possible overflow in HID/intel-ish-hid/ipc
      (bsc#1220920).

  * CVE-2023-52529: Fixed a potential memory leak in sony_probe() (bsc#1220929).

  * CVE-2023-52474: Fixed a vulnerability with non-PAGE_SIZE-end multi-iovec
      user SDMA requests (bsc#1220445).

  * CVE-2023-52513: Fixed connection failure handling in RDMA/siw (bsc#1221022).

  * CVE-2023-52515: Fixed possible use-after-free in RDMA/srp (bsc#1221048).

  * CVE-2023-52564: Reverted invalid fix for UAF in gsm_cleanup_mux()
      (bsc#1220938).

  * CVE-2023-52447: Fixed map_fd_put_ptr() signature kABI workaround
      (bsc#1220251).

  * CVE-2023-52510: Fixed a potential UAF in ca8210_probe() (bsc#1220898).

  * CVE-2023-52524: Fixed possible corruption in nfc/llcp (bsc#1220927).

  * CVE-2023-52528: Fixed uninit-value access in __smsc75xx_read_reg()
      (bsc#1220843).

  * CVE-2023-52507: Fixed possible shift-out-of-bounds in nfc/nci (bsc#1220833).

  * CVE-2023-52566: Fixed potential use after free in
      nilfs_gccache_submit_read_data() (bsc#1220940).

  * CVE-2023-52508: Fixed null pointer dereference in nvme_fc_io_getuuid()
      (bsc#1221015).

  * CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request
      (bsc#1217988).

  * CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete
      (bsc#1217989).

  * CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec
      (bsc#1217987).

  * CVE-2023-52454: Fixed a kernel panic when host sends an invalid H2C PDU
      length (bsc#1220320).

  * CVE-2023-52520: Fixed reference leak in platform/x86/think-lmi
      (bsc#1220921).

  * CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work()
      (bsc#1212514).

  * CVE-2023-52509: Fixed a use-after-free issue in ravb_tx_timeout_work()
      (bsc#1220836).

  * CVE-2023-52501: Fixed possible memory corruption in ring-buffer
      (bsc#1220885).

  * CVE-2023-52567: Fixed possible Oops in serial/8250_port: when using IRQ
      polling (irq = 0) (bsc#1220839).

  * CVE-2023-52517: Fixed race between DMA RX transfer completion and RX FIFO
      drain in spi/sun6i (bsc#1221055).

  * CVE-2023-52511: Fixed possible memory corruption in spi/sun6i (bsc#1221012).

  * CVE-2023-52525: Fixed o ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
