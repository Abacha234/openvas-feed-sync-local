# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856111");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-27913", "CVE-2024-31948");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 14:55:08 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-05-07 01:00:22 +0000 (Tue, 07 May 2024)");
  script_name("openSUSE: Security Advisory for frr (SUSE-SU-2024:1453-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1453-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WJ2FWDLFPJTI5HCBZSB66FEB3VC4NDCF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the SUSE-SU-2024:1453-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for frr fixes the following issues:

  * CVE-2024-27913: Fixed a denial of service issue via a malformed OSPF LSA
      packet (bsc#1220548).

  * CVE-2024-31948: Fixed denial of service due to malformed Prefix SID
      attribute in BGP Update packet (bsc#1222518).

  ##");

  script_tag(name:"affected", value:"'frr' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
