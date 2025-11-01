# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833051");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-22967");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 19:24:31 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:19:46 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for salt (SUSE-SU-2022:2178-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2178-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/66P7KI2PEYJT2DJS6HH4B5ULEDCMO5IP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the SUSE-SU-2022:2178-2 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

  - CVE-2022-22967: Fixed missing check for PAM_ACCT_MGM return value that
       could be used to bypass PAM authentication (bsc#1200566)");

  script_tag(name:"affected", value:"'salt' package(s) on openSUSE Leap Micro 5.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
