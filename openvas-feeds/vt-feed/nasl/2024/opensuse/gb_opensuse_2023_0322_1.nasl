# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833104");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2006-20001", "CVE-2022-36760", "CVE-2022-37436");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 19:21:21 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:20:03 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for apache2 (SUSE-SU-2023:0322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0322-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4BITEDEC4Y4BMTFNOYODTO5INYTDLOQE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the SUSE-SU-2023:0322-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes the following issues:

  - CVE-2022-37436: Fixed an issue in mod_proxy where a malicious backend
       could cause the response headers to be truncated early, resulting in
       some headers being incorporated into the response body (bsc#1207251).

  - CVE-2022-36760: Fixed an issue in mod_proxy_ajp that could allow request
       smuggling attacks (bsc#1207250).

  - CVE-2006-20001: Fixed an issue in mod_proxy_ajp where a request header
       could cause memory corruption (bsc#1207247).");

  script_tag(name:"affected", value:"'apache2' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
