# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833460");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-42794", "CVE-2023-42795", "CVE-2023-45648", "CVE-2023-46589", "CVE-2024-22029");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 19:11:01 +0000 (Mon, 04 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:08 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for tomcat (SUSE-SU-2024:0472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0472-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3HXFEE3YNN3HB3CQUOCZVGO4RXN5FUIO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the SUSE-SU-2024:0472-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:

  Updated to Tomcat 9.0.85:

  * CVE-2023-45648: Improve trailer header parsing (bsc#1216118).

  * CVE-2023-42794: FileUpload: remove tmp files to avoid DoS on Windows
      (bsc#1216120).

  * CVE-2023-42795: Improve handling of failures during recycle() methods
      (bsc#1216119).

  * CVE-2023-46589: Fixed HTTP request smuggling due to incorrect headers
      parsing (bsc#1217649)

  * CVE-2024-22029: Fixed escalation to root from tomcat user via %post script.
      (bsc#1219208)

  The following non-security issues were fixed:

  * Fixed the file permissions for server.xml (bsc#1217768, bsc#1217402).");

  script_tag(name:"affected", value:"'tomcat' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
