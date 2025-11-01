# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856917");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2023-28450", "CVE-2023-50387", "CVE-2023-50868");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2025-01-11 05:01:06 +0000 (Sat, 11 Jan 2025)");
  script_name("openSUSE: Security Advisory for dnsmasq (SUSE-SU-2025:0071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0071-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DEKEI5FJUPSMQTBELI6LN6TJE2OPRJLZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the SUSE-SU-2025:0071-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dnsmasq fixes the following issues:

  * Version update to 2.90:

  * CVE-2023-50387: Fixed a Denial Of Service while trying to validate specially
      crafted DNSSEC responses. (bsc#1219823)

  * CVE-2023-50868: Fixed a Denial Of Service while trying to validate specially
      crafted DNSSEC responses. (bsc#1219826)

  * CVE-2023-28450: Default maximum EDNS.0 UDP packet size should be 1232.
      (bsc#1209358)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
