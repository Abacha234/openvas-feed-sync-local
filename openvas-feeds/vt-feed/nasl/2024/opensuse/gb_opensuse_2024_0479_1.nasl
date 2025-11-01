# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833297");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-5676", "CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20926", "CVE-2024-20945", "CVE-2024-20952");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:42 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:52:08 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:0479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0479-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SMOSC6IMM355PBANEWOTHBQSMF3QTFSN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:0479-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openj9 fixes the following issues:

  Update to OpenJDK 8u402 build 06 with OpenJ9 0.43.0 virtual machine

  * Including OpenJ9 0.41.0 fixes of CVE-2023-5676, bsc#1217214

  * CVE-2024-20918 (bsc#1218907), CVE-2024-20919 (bsc#1218903), CVE-2024-20921
      (bsc#1218905), CVE-2024-20926 (bsc#1218906), CVE-2024-20945 (bsc#1218909),
      CVE-2024-20952 (bsc#1218911)

  ##");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
