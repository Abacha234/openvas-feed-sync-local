# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833424");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20932", "CVE-2024-20945", "CVE-2024-20952");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:40 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:36 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:0325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0325-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SFD3G7ZERNOC2QGHEJ4I3UDIMBQBRYDI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:0325-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:

  Updated to version 17.0.10 (January 2024 CPU):

  * CVE-2024-20918: Fixed an out of bounds access in the Hotspot JVM due to a
      missing bounds check (bsc#1218907).

  * CVE-2024-20919: Fixed a sandbox bypass in the Hotspot JVM class file
      verifier (bsc#1218903).

  * CVE-2024-20921: Fixed an incorrect optimization in the Hotspot JVM that
      could lead to corruption of JVM memory (bsc#1218905).

  * CVE-2024-20932: Fixed an incorrect handling of ZIP files with duplicate
      entries (bsc#1218908).

  * CVE-2024-20945: Fixed a potential private key leak through debug logs
      (bsc#1218909).

  * CVE-2024-20952: Fixed an RSA padding issue and timing side-channel attack
      against TLS (bsc#1218911).");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
