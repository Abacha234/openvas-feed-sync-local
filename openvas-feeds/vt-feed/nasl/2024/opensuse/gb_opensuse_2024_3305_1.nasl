# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856490");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-20505", "CVE-2024-20506");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-12 17:28:47 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-20 04:00:29 +0000 (Fri, 20 Sep 2024)");
  script_name("openSUSE: Security Advisory for clamav (SUSE-SU-2024:3305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3305-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WG6XZ5NQZX3JZVWRMH5YPHETRG6BNJDE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the SUSE-SU-2024:3305-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

  * Update to version 0.103.12

  * CVE-2024-20506: Disable symlinks following to prevent an attacker to corrupt
      system files. (bsc#1230162)

  * CVE-2024-20505: Fixed possible out-of-bounds read bug in the PDF file
      parser. (bsc#1230161)");

  script_tag(name:"affected", value:"'clamav' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
