# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833056");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-20588", "CVE-2023-34322", "CVE-2023-34325", "CVE-2023-34326", "CVE-2023-34327", "CVE-2023-34328", "CVE-2023-46835", "CVE-2023-46836");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 15:57:03 +0000 (Thu, 11 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:35:57 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xen (SUSE-SU-2023:4476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4476-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YTMYKHGIILBOPUE3WHG2JZMD7SBCOHJO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the SUSE-SU-2023:4476-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  * CVE-2023-20588: AMD CPU transitional execution leak via division by zero
      (XSA-439) (bsc#1215474).

  * CVE-2023-34322: top-level shadow reference dropped too early for 64-bit PV
      guests (XSA-438) (bsc#1215145).

  * CVE-2023-34325: Multiple vulnerabilities in libfsimage disk handling
      (XSA-443) (bsc#1215747).

  * CVE-2023-34326: x86/AMD: missing IOMMU TLB flushing (XSA-442) (bsc#1215746).

  * CVE-2023-34327, CVE-2023-34328: x86/AMD: Debug Mask handling (XSA-444)
      (bsc#1215748).

  * CVE-2023-46835: x86/AMD: mismatch in IOMMU quarantine page table levels
      (XSA-445) (bsc#1216654).

  * CVE-2023-46836: x86: BTC/SRSO fixes not fully effective (XSA-446)
      (bsc#1216807).

  * Upstream bug fixes (bsc#1027519)

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
