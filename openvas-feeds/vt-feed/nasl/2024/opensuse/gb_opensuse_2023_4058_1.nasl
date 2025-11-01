# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833639");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-1192", "CVE-2023-1206", "CVE-2023-1859", "CVE-2023-2177", "CVE-2023-37453", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-40283", "CVE-2023-4155", "CVE-2023-42753", "CVE-2023-42754", "CVE-2023-4389", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921", "CVE-2023-5345");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-04 20:56:10 +0000 (Wed, 04 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:43:29 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:4058-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4058-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/L32HPZ6QSGLBJVE5VEYAOXGYVYAZ5A6A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:4058-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2023-39192: Fixed an out of bounds read in the netfilter (bsc#1215858).

  * CVE-2023-39193: Fixed an out of bounds read in the xtables subsystem
      (bsc#1215860).

  * CVE-2023-39194: Fixed an out of bounds read in the XFRM subsystem
      (bsc#1215861).

  * CVE-2023-42754: Fixed a NULL pointer dereference in the IPv4 stack that
      could lead to denial of service (bsc#1215467).

  * CVE-2023-4389: Fixed a reference counting issue in the Btrfs filesystem that
      could be exploited in order to leak internal kernel information or crash the
      system (bsc#1214351).

  * CVE-2023-5345: fixed an use-after-free vulnerability in the fs/smb/client
      component which could be exploited to achieve local privilege escalation
      (bsc#1215899).

  * CVE-2023-42753: Fixed an array indexing vulnerability in the netfilter
      subsystem. This issue may have allowed a local user to crash the system or
      potentially escalate their privileges (bsc#1215150).

  * CVE-2023-1206: Fixed a hash collision flaw in the IPv6 connection lookup
      table which could be exploited by network adjacent attackers, increasing CPU
      usage by 95% (bsc#1212703).

  * CVE-2023-4921: Fixed a use-after-free vulnerability in the QFQ network
      scheduler which could be exploited to achieve local privilege escalatio
      (bsc#1215275).

  * CVE-2023-37453: Fixed oversight in SuperSpeed initialization (bsc#1213123).

  * CVE-2023-4622: Fixed a use-after-free vulnerability in the Unix domain
      sockets component which could be exploited to achieve local privilege
      escalation (bsc#1215117).

  * CVE-2023-4623: Fixed a use-after-free issue in the HFSC network scheduler
      which could be exploited to achieve local privilege escalation
      (bsc#1215115).

  * CVE-2023-4155: Fixed a flaw in KVM AMD Secure Encrypted Virtualization
      (SEV). An attacker can trigger a stack overflow and cause a denial of
      service or potentially guest-to-host escape in kernel configurations without
      stack guard pages (bsc#1214022).

  * CVE-2023-1859: Fixed a use-after-free flaw in Xen transport for 9pfs which
      could be exploited to crash the system (bsc#1210169).

  * CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem
      that could lead to potential information disclosure or a denial of service
      (bsc#1215221).

  * CVE-2023-2177: Fixed a null pointer dereference issue in the sctp netwo ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
