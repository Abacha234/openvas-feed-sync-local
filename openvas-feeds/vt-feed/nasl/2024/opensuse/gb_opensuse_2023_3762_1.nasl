# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833672");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38802", "CVE-2023-41358", "CVE-2023-41909");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-08 16:49:26 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:02 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for frr (SUSE-SU-2023:3762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3762-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QCORWO2RQHAPR6DKBB6PGZFOXJY4PQPK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the SUSE-SU-2023:3762-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for frr fixes the following issues:

  * CVE-2023-38802: Fixed bad length handling when processing BGP attributes.
      (bsc#1213284)

  * CVE-2023-41358: Fixed a possible crash when processing NLRIs with an
      attribute length of zero. (bsc#1214735)

  * CVE-2023-41909: Fixed NULL pointer dereference due to processing in
      bgp_nlri_parse_flowspec (bsc#1215065).

  ##");

  script_tag(name:"affected", value:"'frr' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
