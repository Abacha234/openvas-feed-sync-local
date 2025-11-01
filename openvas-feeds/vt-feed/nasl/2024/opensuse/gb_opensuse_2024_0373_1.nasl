# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856733");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-11110", "CVE-2024-11111", "CVE-2024-11112", "CVE-2024-11113", "CVE-2024-11114", "CVE-2024-11115", "CVE-2024-11116", "CVE-2024-11117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 18:00:46 +0000 (Thu, 02 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-11-23 05:00:20 +0000 (Sat, 23 Nov 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2024:0373-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0373-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GW7TPS22DZK4SYF2WPZQO6RF5P6FPPAV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2024:0373-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 131.0.6778.69 (stable released 2024-11-12) (boo#1233311)

  * CVE-2024-11110: Inappropriate implementation in Blink.

  * CVE-2024-11111: Inappropriate implementation in Autofill.

  * CVE-2024-11112: Use after free in Media.

  * CVE-2024-11113: Use after free in Accessibility.

  * CVE-2024-11114: Inappropriate implementation in Views.

  * CVE-2024-11115: Insufficient policy enforcement in Navigation.

  * CVE-2024-11116: Inappropriate implementation in Paint.

  * CVE-2024-11117: Inappropriate implementation in FileSystem.");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
