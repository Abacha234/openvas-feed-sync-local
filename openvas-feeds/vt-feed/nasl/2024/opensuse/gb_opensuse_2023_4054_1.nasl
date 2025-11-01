# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833122");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-34323", "CVE-2023-34325", "CVE-2023-34326", "CVE-2023-34327", "CVE-2023-34328");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 15:57:03 +0000 (Thu, 11 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:33:38 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xen (SUSE-SU-2023:4054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4054-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NM4ZW22BXU6O4FT53YX7QRB4OZ7P3AQO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the SUSE-SU-2023:4054-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  * CVE-2023-34323: A transaction conflict can crash C Xenstored (XSA-440,
      bsc#1215744)

  * CVE-2023-34326: Missing IOMMU TLB flushing (XSA-442, bsc#1215746)

  * CVE-2023-34325: Multiple vulnerabilities in libfsimage disk handling
      (XSA-443, bsc#1215747)

  * CVE-2023-34327: Debug Mask handling (XSA-444, bsc#1215748)

  * CVE-2023-34328: Debug Mask handling (XSA-444, bsc#1215748)

  ##");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
