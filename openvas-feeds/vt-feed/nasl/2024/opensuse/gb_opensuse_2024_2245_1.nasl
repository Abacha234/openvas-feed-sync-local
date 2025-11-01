# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856251");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38406", "CVE-2023-38407", "CVE-2023-47234", "CVE-2023-47235");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 20:03:32 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-06-29 04:00:32 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for frr (SUSE-SU-2024:2245-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2245-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZSD5DV4BAQZAYRQ26BDFVK3ZZC3LHFNV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the SUSE-SU-2024:2245-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for frr fixes the following issues:

  * CVE-2023-38406: Fixed nlri length of zero mishandling, aka 'flowspec
      overflow'. (bsc#1216900)

  * CVE-2023-47235: Fixed a crash on malformed BGP UPDATE message with an EOR,
      because the presence of EOR does not lead to a treat-as-withdraw outcome.
      (bsc#1216896)

  * CVE-2023-47234: Fixed a crash on crafted BGP UPDATE message with a
      MP_UNREACH_NLRI attribute and additional NLRI data. (bsc#1216897)

  * CVE-2023-38407: Fixed attempts to read beyond the end of the stream during
      labeled unicast parsing. (bsc#1216899)

  ##");

  script_tag(name:"affected", value:"'frr' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
