# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833879");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-20251", "CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32745", "CVE-2022-32746", "CVE-2022-3437", "CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023", "CVE-2022-42898");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 20:28:07 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:23:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for samba (SUSE-SU-2023:0160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0160-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZOBTTQFF6GG7YAS7P57L3YTPEJ3NCLRE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the SUSE-SU-2023:0160-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

  - CVE-2021-20251: Fixed an issue where the bad password count would not be
       properly incremented, which could allow attackers to brute force a
       user's password (bsc#1206546).

  - Updated to version 4.15.13:

  - CVE-2022-37966: Fixed an issue where a weak cipher would be selected
         to encrypt session keys, which could lead to privilege escalation
         (bsc#1205385).

  - CVE-2022-37967: Fixed a potential privilege escalation issue via
         constrained delegation due to weak a cryptographic algorithm being
         selected (bsc#1205386).

  - CVE-2022-38023: Disabled weak ciphers by default in the Netlogon
         Secure channel (bsc#1206504).

  - Updated to version 4.15.12:

  - CVE-2022-42898: Fixed several buffer overflow vulnerabilities on
         32-bit systems (bsc#1205126).

  - Updated to version 4.15.11:

  - CVE-2022-3437: Fixed a buffer overflow in Heimdal unwrap_des3()
         (bsc#1204254).

  - Updated to version 4.15.10:

  - Fixed a potential crash due to a concurrency issue (bsc#1200102).

  - Updated to version 4.15.9:

  - CVE-2022-32742: Fixed an information leak that could be triggered via
         SMB1 (bsc#1201496).

  - CVE-2022-32746: Fixed a memory corruption issue in database audit
         logging (bsc#1201490).

  - CVE-2022-2031: Fixed AD restrictions bypass associated with changing
         passwords (bsc#1201495).

  - CVE-2022-32745: Fixed a remote server crash that could be triggered
         with certain LDAP requests (bsc#1201492).

  - CVE-2022-32744: Fixed an issue where AD users could have forged
         password change requests on behalf of other users (bsc#1201493).

     Other fixes:

  - Fixed a problem when using bind as samba-ad-dc backend related to the
       named service (bsc#1201689).");

  script_tag(name:"affected", value:"'samba' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
