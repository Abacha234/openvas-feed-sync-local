# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833283");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-46835", "CVE-2023-46836");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 15:56:04 +0000 (Thu, 11 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:34:41 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xen (SUSE-SU-2023:4466-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4466-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CXZZTJWZ7ZD4LFR5CDZCXMDRHNXOQYBQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the SUSE-SU-2023:4466-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  * CVE-2023-46835: x86/AMD: mismatch in IOMMU quarantine page table levels
      (XSA-445) (bsc#1216654).

  * CVE-2023-46836: x86: BTC/SRSO fixes not fully effective (XSA-446)
      (bsc#1216807).

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
