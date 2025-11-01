# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856214");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-6516");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:46 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:00:22 +0000 (Sat, 15 Jun 2024)");
  script_name("openSUSE: Security Advisory for bind (SUSE-SU-2024:1982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1982-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VAX65UD6RDJH727M3NIGIC5ZJAYJ63HG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the SUSE-SU-2024:1982-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  * CVE-2023-4408: Fixed denial of service during DNS message parsing with
      different names (bsc#1219851)

  * CVE-2023-50387: Fixed denial of service during DNS messages validation with
      DNSSEC signatures (bsc#1219823)

  * CVE-2023-50868: Fixed denial of service during NSEC3 closest encloser proof
      preparation (bsc#1219826)

  * CVE-2023-5517: Fixed denial of service caused by specific queries with
      nxdomain-redirect enabled (bsc#1219852)

  * CVE-2023-6516: Fixed denial of service caused by specific queries that
      continuously triggered cache database maintenance (bsc#1219854)

  ##");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
