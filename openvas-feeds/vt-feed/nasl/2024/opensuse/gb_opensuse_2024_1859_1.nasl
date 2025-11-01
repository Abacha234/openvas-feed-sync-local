# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856356");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38264", "CVE-2024-21011", "CVE-2024-21012", "CVE-2024-21068", "CVE-2024-21085", "CVE-2024-21094");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-14 13:21:29 +0000 (Tue, 14 May 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:49 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:1859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1859-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TIV7ZAF6SC76GAAJ3UF2EMATJZA2OLKX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:1859-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

  Update to Java 8.0 Service Refresh 8 Fix Pack 25 (bsc#1223470):

  * CVE-2023-38264: Fixed Object Request Broker (ORB) denial of service
      (bsc#1224164).

  * CVE-2024-21094: Fixed C2 compilation fails with 'Exceeded _node_regs array'
      (bsc#1222986).

  * CVE-2024-21068: Fixed integer overflow in C1 compiler address generation
      (bsc#1222983).

  * CVE-2024-21085: Fixed Pack200 excessive memory allocation (bsc#1222984).

  * CVE-2024-21011: Fixed Long Exception message leading to crash (bsc#1222979).

  * CVE-2024-21012: Fixed HTTP/2 client improper reverse DNS lookup
      (bsc#1222987).

  ##");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
