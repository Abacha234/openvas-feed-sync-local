# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833691");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-4415");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 18:07:28 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:01 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for systemd (SUSE-SU-2023:0201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0201-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BLK5EOKG33ZTGWYBK24RD7RG4QEH3ZES");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the SUSE-SU-2023:0201-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  - CVE-2022-4415: Fixed an issue where users could access coredumps with
       changed uid, gid or capabilities (bsc#1205000).

     Non-security fixes:

  - Enabled the pstore service (jsc#PED-2663).

  - Fixed an issue accessing TPM when secure boot is enabled (bsc#1204944).

  - Fixed an issue where a pamd file could get accidentally overwritten
       after an update (bsc#1207264).


  Special Instructions and Notes:

     Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'systemd' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
