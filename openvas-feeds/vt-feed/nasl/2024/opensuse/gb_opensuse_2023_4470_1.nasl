# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833509");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-45283", "CVE-2023-45284");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-17 16:39:56 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.20 (SUSE-SU-2023:4470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4470-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XITZYMDBAT2MDE26RIRILOZQRR4CIL4O");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.20'
  package(s) announced via the SUSE-SU-2023:4470-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.20 fixes the following issues:

  go1.20.11 (released 2023-11-07) includes security fixes to the path/filepath
  package, as well as bug fixes to the linker and the net/http package.

  * security: fix CVE-2023-45283 CVE-2023-45284 path/filepath: insecure parsing
      of Windows paths (bsc#1216943, bsc#1216944)

  * cmd/link: split text sections for arm 32-bit

  * net/http: http2 page fails on firefox/safari if pushing resources

  ##");

  script_tag(name:"affected", value:"'go1.20' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
