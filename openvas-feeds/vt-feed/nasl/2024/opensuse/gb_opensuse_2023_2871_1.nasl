# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833854");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-36280", "CVE-2022-38096", "CVE-2022-4269", "CVE-2022-45884", "CVE-2022-45885", "CVE-2022-45886", "CVE-2022-45887", "CVE-2022-45919", "CVE-2022-4744", "CVE-2023-0045", "CVE-2023-0122", "CVE-2023-0179", "CVE-2023-0394", "CVE-2023-0461", "CVE-2023-0469", "CVE-2023-0590", "CVE-2023-0597", "CVE-2023-1075", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1079", "CVE-2023-1095", "CVE-2023-1118", "CVE-2023-1249", "CVE-2023-1382", "CVE-2023-1513", "CVE-2023-1582", "CVE-2023-1583", "CVE-2023-1611", "CVE-2023-1637", "CVE-2023-1652", "CVE-2023-1670", "CVE-2023-1829", "CVE-2023-1838", "CVE-2023-1855", "CVE-2023-1989", "CVE-2023-1998", "CVE-2023-2002", "CVE-2023-21102", "CVE-2023-21106", "CVE-2023-2124", "CVE-2023-2156", "CVE-2023-2162", "CVE-2023-2176", "CVE-2023-2235", "CVE-2023-2269", "CVE-2023-22998", "CVE-2023-23000", "CVE-2023-23001", "CVE-2023-23004", "CVE-2023-23006", "CVE-2023-2430", "CVE-2023-2483", "CVE-2023-25012", "CVE-2023-2513", "CVE-2023-26545", "CVE-2023-28327", "CVE-2023-28410", "CVE-2023-28464", "CVE-2023-28866", "CVE-2023-3006", "CVE-2023-30456", "CVE-2023-30772", "CVE-2023-3090", "CVE-2023-31084", "CVE-2023-3111", "CVE-2023-3141", "CVE-2023-31436", "CVE-2023-3161", "CVE-2023-3212", "CVE-2023-3220", "CVE-2023-32233", "CVE-2023-33288", "CVE-2023-3357", "CVE-2023-3358", "CVE-2023-3389", "CVE-2023-33951", "CVE-2023-33952", "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35828", "CVE-2023-35829");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:38:22 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:2871-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2871-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5B4FN45ULO6TI53ZXGRZJDNBPHCPMIRP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:2871-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security
  and bugfixes.

  The following security bugs were fixed:

  * CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in
      vmwgfx driver (bsc#1203332).

  * CVE-2022-38096: Fixed NULL-ptr deref in vmw_cmd_dx_define_query()
      (bsc#1203331).

  * CVE-2022-4269: Fixed a flaw was found inside the Traffic Control (TC)
      subsystem (bsc#1206024).

  * CVE-2022-45884: Fixed a use-after-free in dvbdev.c, related to
      dvb_register_device dynamically allocating fops (bsc#1205756).

  * CVE-2022-45885: Fixed a race condition in dvb_frontend.c that could cause a
      use-after-free when a device is disconnected (bsc#1205758).

  * CVE-2022-45886: Fixed a .disconnect versus dvb_device_open race condition in
      dvb_net.c that lead to a use-after-free (bsc#1205760).

  * CVE-2022-45887: Fixed a memory leak in ttusb_dec.c caused by the lack of a
      dvb_frontend_detach call (bsc#1205762).

  * CVE-2022-45919: Fixed a use-after-free in dvb_ca_en50221.c that could occur
      if there is a disconnect after an open, because of the lack of a wait_event
      (bsc#1205803).

  * CVE-2022-4744: Fixed double-free that could lead to DoS or privilege
      escalation in TUN/TAP device driver functionality (bsc#1209635).

  * CVE-2023-0045: Fixed missing Flush IBP in ib_prctl_set (bsc#1207773).

  * CVE-2023-0122: Fixed a NULL pointer dereference vulnerability in
      nvmet_setup_auth(), that allowed an attacker to perform a Pre-Auth Denial of
      Service (DoS) attack on a remote machine (bsc#1207050).

  * CVE-2023-0179: Fixed incorrect arithmetic when fetching VLAN header bits
      (bsc#1207034).

  * CVE-2023-0394: Fixed a null pointer dereference in the network subcomponent.
      This flaw could cause system crashes (bsc#1207168).

  * CVE-2023-0461: Fixed use-after-free in icsk_ulp_data (bsc#1208787).

  * CVE-2023-0469: Fixed a use-after-free flaw in io_uring/filetable.c in
      io_install_fixed_file in the io_uring subcomponent (bsc#1207521).

  * CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).

  * CVE-2023-0597: Fixed lack of randomization of per-cpu entry area in x86/mm
      (bsc#1207845).

  * CVE-2023-1075: Fixed a type confusion in tls_is_tx_ready (bsc#1208598).

  * CVE-2023-1076: Fixed incorrect UID assigned to tun/tap sockets
      (bsc#1208599).

  * CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could
      cause memory corruption (bsc#1208600).

  * CVE-2023-1079: Fixed a use-after-free problem  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
