# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856178");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-21011", "CVE-2024-21068", "CVE-2024-21085", "CVE-2024-21094");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-16 22:15:29 +0000 (Tue, 16 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-06-05 01:00:45 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:1793-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1793-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V4EQAQE4AT4H62CTUKIIW2NXQSRR3HHA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:1793-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openj9 fixes the following issues:

  Update to OpenJDK 8u412 build 08 with OpenJ9 0.44.0 virtual machine:

  * CVE-2024-21094: Fixed C2 compilation failure with 'Exceeded _node_regs
      array' (bsc#1222986).

  * CVE-2024-21011: Fixed long Exception message leading to crash (bsc#1222979).

  * CVE-2024-21085: Fixed Pack200 excessive memory allocation (bsc#1222984).

  * CVE-2024-21068: Fixed integer overflow in C1 compiler address generation
      (bsc#1222983).

  ##");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
