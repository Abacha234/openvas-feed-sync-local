# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856839");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-21208", "CVE-2024-21210", "CVE-2024-21217", "CVE-2024-21235", "CVE-2024-3933");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 18:00:53 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-12-13 05:00:24 +0000 (Fri, 13 Dec 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:4306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4306-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MXBN2J5OLQHHEFQZKWDMPVG3S6TODMOZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:4306-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

  Updated to Java 8.0 Service Refresh 8 Fix Pack 35 with Oracle October 15 2024
  CPU (bsc#1232064): \- CVE-2024-21208: Fixed partial DoS in component Networking
  (bsc#1231702,JDK-8328286) \- CVE-2024-21210: Fixed unauthorized update, insert
  or delete access to some of Oracle Java SE accessible data in component Hotspot
  (bsc#1231711,JDK-8328544) \- CVE-2024-21217: Fixed partial DoS in component
  Serialization (bsc#1231716,JDK-8331446) \- CVE-2024-21235: Fixed unauthorized
  read/write access to data in component Hotspot (bsc#1231719,JDK-8332644)

  Other issues fixed in past releases: \- CVE-2024-3933: Fixed evaluate constant
  byteLenNode of arrayCopyChild (bsc#1225470)");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
