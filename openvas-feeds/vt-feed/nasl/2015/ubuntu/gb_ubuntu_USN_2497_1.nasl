# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842087");
  script_cve_id("CVE-2014-9297", "CVE-2014-9298");
  script_tag(name:"creation_date", value:"2015-02-10 04:30:53 +0000 (Tue, 10 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2497-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2497-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-2497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephen Roettger, Sebastian Krahmer, and Harlan Stenn discovered that NTP
incorrectly handled the length value in extension fields. A remote attacker
could use this issue to possibly obtain leaked information, or cause the
NTP daemon to crash, resulting in a denial of service. (CVE-2014-9297)

Stephen Roettger discovered that NTP incorrectly handled ACLs based on
certain IPv6 addresses. (CVE-2014-9298)");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
