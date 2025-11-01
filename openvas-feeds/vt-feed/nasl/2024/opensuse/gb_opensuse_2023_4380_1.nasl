# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833661");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-46724", "CVE-2023-46846", "CVE-2023-46847", "CVE-2023-46848");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 20:03:23 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:33:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for squid (SUSE-SU-2023:4380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4380-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3OJ7EFCESPLKL2J3U4WBON5SUX2BM5BJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the SUSE-SU-2023:4380-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid fixes the following issues:

  * CVE-2023-46846: Request/Response smuggling in HTTP/1.1 and ICAP
      (bsc#1216500).

  * CVE-2023-46847: Denial of Service in HTTP Digest Authentication
      (bsc#1216495).

  * CVE-2023-46724: Fix validation of certificates with CN=* (bsc#1216803).

  * CVE-2023-46848: Denial of Service in FTP (bsc#1216498).

  ##");

  script_tag(name:"affected", value:"'squid' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
