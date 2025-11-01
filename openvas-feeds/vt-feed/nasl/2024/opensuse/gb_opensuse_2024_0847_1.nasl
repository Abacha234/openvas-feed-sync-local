# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856024");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20926", "CVE-2024-20945", "CVE-2024-20952");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:42 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:30:06 +0000 (Mon, 25 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:0847-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0847-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7G66UBHPARGMQZONUFYZRGFIS4TGWHW4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:0847-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

  * CVE-2024-20952: Fixed RSA padding issue and timing side-channel attack
      against TLS (8317547) (bsc#1218911).

  * CVE-2024-20921: Fixed range check loop optimization issue (8314307)
      (bsc#1218905).

  * CVE-2024-20926: Fixed rbitrary Java code execution in Nashorn (8314284)
      (bsc#1218906).

  * CVE-2024-20919: Fixed JVM class file verifier flaw allows unverified byte
      code execution (8314295) (bsc#1218903).

  * CVE-2024-20918: Fixed array out-of-bounds access due to missing range check
      in C1 compiler (8314468) (bsc#1218907).

  * CVE-2024-20945: Fixed logging of digital signature private keys (8316976)
      (bsc#1218909).

  Update to version jdk8u402 (icedtea-3.30.0).

  ##");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
