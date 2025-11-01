# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856697");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-36474", "CVE-2024-42415");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-09 16:44:20 +0000 (Wed, 09 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-08 05:00:30 +0000 (Fri, 08 Nov 2024)");
  script_name("openSUSE: Security Advisory for libgsf (SUSE-SU-2024:3920-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3920-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4BY3OZ53IH2MNA6OLS63XSXXXCO7DIWX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgsf'
  package(s) announced via the SUSE-SU-2024:3920-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgsf fixes the following issues:

  * CVE-2024-42415, CVE-2024-36474: Fixed integer overflows affecting memory
      allocation (bsc#1231282, bsc#1231283).");

  script_tag(name:"affected", value:"'libgsf' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
