# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833540");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-32731", "CVE-2023-32732", "CVE-2023-33953", "CVE-2023-44487", "CVE-2023-4785");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-19 16:02:53 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for abseil (SUSE-SU-2024:0573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0573-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A335QSYHJ3DSMHQJB4PZLCVP3IMMYCTE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abseil'
  package(s) announced via the SUSE-SU-2024:0573-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for abseil-cpp, grpc, opencensus-proto, protobuf, python-abseil,
  python-grpcio, re2 fixes the following issues:

  abseil-cpp was updated to:

  Update to 20230802.1:

  * Add StdcppWaiter to the end of the list of waiter implementations

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'abseil' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
