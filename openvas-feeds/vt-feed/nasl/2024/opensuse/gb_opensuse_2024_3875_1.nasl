# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856678");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-21208", "CVE-2024-21210", "CVE-2024-21217", "CVE-2024-21235");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:12 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-02 05:01:14 +0000 (Sat, 02 Nov 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:3875-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3875-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GLU5JTTGFTD7YI4RRECCJZQWTOZHUSNK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:3875-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

  Updated to version 11.0.25+9 (October 2024 CPU):

  * CVE-2024-21208: Fixed partial DoS in component Networking (bsc#1231702)

  * CVE-2024-21210: Fixed unauthorized read/write access to data in component
      Hotspot (bsc#1231711)

  * CVE-2024-21217: Fixed partial DoS in component Serialization (bsc#1231716)

  * CVE-2024-21235: Fixed unauthorized read/write access to data in component
      Hotspot (bsc#1231719)");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
