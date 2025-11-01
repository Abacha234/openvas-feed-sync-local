# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833398");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-51765", "CVE-2023-5176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:47 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-08 02:01:10 +0000 (Fri, 08 Mar 2024)");
  script_name("openSUSE: Security Advisory for sendmail (SUSE-SU-2024:0743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0743-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TAMS3GYWXYSKFZUOXMRAQMVTQKX2I74G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sendmail'
  package(s) announced via the SUSE-SU-2024:0743-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sendmail fixes the following issues:

  * CVE-2023-51765: Fixed new SMTP smuggling attack. (bsc#1218351)

  ##");

  script_tag(name:"affected", value:"'sendmail' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
