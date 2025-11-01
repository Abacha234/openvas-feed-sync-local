# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856489");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-23984", "CVE-2024-24968");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-09-20 04:00:27 +0000 (Fri, 20 Sep 2024)");
  script_name("openSUSE: Security Advisory for ucode (SUSE-SU-2024:3332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3332-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A53UL5PPNSCLERJH4JPIPXJ2PZZ6ENPZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode'
  package(s) announced via the SUSE-SU-2024:3332-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  * Intel CPU Microcode was updated to the 20240910 release (bsc#1230400)

  * CVE-2024-23984: Observable discrepancy in RAPL interface for some Intel
      Processors may allow a privileged user to potentially enable information
      disclosure via local access.

  * CVE-2024-24968: Improper finite state machines (FSMs) in hardware logic in
      some Intel Processors may allow an privileged user to potentially enable a
      denial of service via local access.

   Special Instructions and Notes:

  * Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'ucode' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
