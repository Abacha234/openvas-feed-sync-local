# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856698");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-46951", "CVE-2024-46953", "CVE-2024-46955", "CVE-2024-46956");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-14 02:01:09 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-08 05:00:32 +0000 (Fri, 08 Nov 2024)");
  script_name("openSUSE: Security Advisory for ghostscript (SUSE-SU-2024:3941-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3941-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TZB53HSOSSBHANRB2PL7HMID2BVO73DG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the SUSE-SU-2024:3941-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript fixes the following issues:

  * CVE-2024-46951: Fixed arbitrary code execution via unchecked
      'Implementation' pointer in 'Pattern' color space (bsc#1232265).

  * CVE-2024-46953: Fixed integer overflow when parsing the page format results
      in path truncation, path traversal, code execution (bsc#1232267).

  * CVE-2024-46956: Fixed arbitrary code execution via out of bounds data access
      in filenameforall (bsc#1232270).

  * CVE-2024-46955: Fixed out of bounds read when reading color in 'Indexed'
      color space (bsc#1232269).");

  script_tag(name:"affected", value:"'ghostscript' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
