# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856195");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-33599", "CVE-2024-33600", "CVE-2024-33601", "CVE-2024-33602");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-06-05 01:01:06 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for glibc (SUSE-SU-2024:1895-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1895-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZYJDGTLL5N2A3QTZDHW775Z2IUNRR7CQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the SUSE-SU-2024:1895-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glibc fixes the following issues:

  * CVE-2024-33599: Fixed a stack-based buffer overflow in netgroup cache in
      nscd (bsc#1223423)

  * CVE-2024-33600: Avoid null pointer crashes after notfound response in nscd
      (bsc#1223424)

  * CVE-2024-33600: Do not send missing not-found response in addgetnetgrentX in
      nscd (bsc#1223424)

  * CVE-2024-33601, CVE-2024-33602: Fixed use of two buffers in addgetnetgrentX
      ( bsc#1223425)

  * CVE-2024-33602: Use time_t for return type of addgetnetgrentX (bsc#1223425)

  * Avoid creating userspace live patching prologue for _start routine
      (bsc#1221940)

  ##");

  script_tag(name:"affected", value:"'glibc' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
