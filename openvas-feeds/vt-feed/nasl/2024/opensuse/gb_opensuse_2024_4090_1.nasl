# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856750");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-31489", "CVE-2023-31490", "CVE-2023-3748", "CVE-2023-38406", "CVE-2023-38407", "CVE-2023-38802", "CVE-2023-41358", "CVE-2023-41360", "CVE-2023-41909", "CVE-2023-46752", "CVE-2023-46753", "CVE-2023-47234", "CVE-2023-47235", "CVE-2024-27913", "CVE-2024-31948", "CVE-2024-31950", "CVE-2024-31951", "CVE-2024-34088", "CVE-2024-44070");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 20:03:32 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-11-29 05:00:31 +0000 (Fri, 29 Nov 2024)");
  script_name("openSUSE: Security Advisory for frr (SUSE-SU-2024:4090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4090-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BBQ2F6B52UDKPMMML6F24O4RGXPC3B6U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the SUSE-SU-2024:4090-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for frr fixes the following issues:

  Update to frr 8.5.6 (jsc#PED-PED-11092) including fixes for:

  * CVE-2024-44070,CVE-2024-34088,CVE-2024-31951,CVE-2024-31950,
      CVE-2024-31948,CVE-2024-27913,CVE-2023-47235,CVE-2023-47234,
      CVE-2023-46753,CVE-2023-46752,CVE-2023-41909,CVE-2023-41360,
      CVE-2023-41358,CVE-2023-38802,CVE-2023-38407,CVE-2023-38406,
      CVE-2023-3748,CVE-2023-31490,CVE-2023-31489 and other bugfixes. See

  The most recent frr 8.x series provides several new features, improvements and
  bug fixes for various protocols and daemons, especially for PIM/PIMv6/BGP and
  VRF support.");

  script_tag(name:"affected", value:"'frr' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
