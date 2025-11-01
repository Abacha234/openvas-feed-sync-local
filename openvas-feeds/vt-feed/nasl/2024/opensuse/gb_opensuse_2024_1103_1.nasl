# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856061");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-1544", "CVE-2023-6693", "CVE-2024-24474", "CVE-2024-26327", "CVE-2024-26328");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 12:46:19 +0000 (Fri, 07 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-04-09 01:06:45 +0000 (Tue, 09 Apr 2024)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2024:1103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1103-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ES5DXAAMYUC767MUW4BPRP6ZPDL6SUW6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2024:1103-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  * CVE-2024-26327: Fixed buffer overflow via invalid SR/IOV NumVFs value
      (bsc#1220062).

  * CVE-2024-24474: Fixed integer overflow results in buffer overflow via SCSI
      command (bsc#1220134).

  * CVE-2023-6693: Fixed stack buffer overflow in virtio_net_flush_tx()
      (bsc#1218484).

  * CVE-2023-1544: Fixed out-of-bounds read in pvrdma_ring_next_elem_read()
      (bsc#1209554).

  * CVE-2024-26328: Fixed invalid NumVFs value handled in NVME SR/IOV
      implementation (bsc#1220065).

  The following non-security bug was fixed:

  * Removing in-use mediated device should fail with error message instead of
      hang (bsc#1205316).

  ##");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
