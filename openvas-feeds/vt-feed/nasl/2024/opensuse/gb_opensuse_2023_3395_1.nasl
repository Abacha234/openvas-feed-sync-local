# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833892");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-40982", "CVE-2023-20569", "CVE-2023-20593");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 19:29:17 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:00 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xen (SUSE-SU-2023:3395-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3395-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AT65WEO6XJOJ3O6MZNVSG4RRKXR5NWEJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the SUSE-SU-2023:3395-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  * CVE-2023-20569: Fixed side channel attack Inception or RAS Poisoning.
      (bsc#1214082, XSA-434)

  * CVE-2022-40982: Fixed transient execution attack called 'Gather Data
      Sampling'. (bsc#1214083, XSA-435)

  * CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an
      attacker to potentially access sensitive information. (bsc#1213616, XSA-433)

  ##");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
