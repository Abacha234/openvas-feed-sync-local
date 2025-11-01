# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856475");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-7256", "CVE-2024-8006");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 17:46:03 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-13 04:00:40 +0000 (Fri, 13 Sep 2024)");
  script_name("openSUSE: Security Advisory for libpcap (SUSE-SU-2024:3217-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3217-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KQZ6UDQQY5PNY7BBJLHGTAD4H77CJUV2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpcap'
  package(s) announced via the SUSE-SU-2024:3217-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libpcap fixes the following issues:

  * CVE-2024-8006: NULL pointer dereference in function pcap_findalldevs_ex().
      (bsc#1230034)

  * CVE-2023-7256: double free via struct addrinfo in function
      sock_initaddress(). (bsc#1230020)

  ##");

  script_tag(name:"affected", value:"'libpcap' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
