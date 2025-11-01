# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833668");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-32360", "CVE-2023-4504");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 20:58:00 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:30:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for cups (SUSE-SU-2023:3707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3707-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M2VJE3TQI6QFP5GVAS4MSBV2O2ZTOIJK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the SUSE-SU-2023:3707-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:

  * CVE-2023-4504: Fixed heap overflow in OpenPrinting CUPS Postscript Parsing
      (bsc#1215204).

  * CVE-2023-32360: Fixed Information leak through Cups-Get-Document operation
      (bsc#1214254).

  ##");

  script_tag(name:"affected", value:"'cups' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
