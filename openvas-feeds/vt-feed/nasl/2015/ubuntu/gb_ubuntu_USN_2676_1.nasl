# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842377");
  script_cve_id("CVE-2013-6410", "CVE-2013-7441", "CVE-2015-0847");
  script_tag(name:"creation_date", value:"2015-07-23 04:27:51 +0000 (Thu, 23 Jul 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2676-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2676-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2676-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbd' package(s) announced via the USN-2676-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that NBD incorrectly handled IP address matching. A
remote attacker could use this issue with an IP address that has a partial
match and bypass access restrictions. This issue only affected
Ubuntu 12.04 LTS. (CVE-2013-6410)

Tuomas Rasanen discovered that NBD incorrectly handled wrong export names
and closed connections during negotiation. A remote attacker could use this
issue to cause NBD to crash, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS. (CVE-2013-7441)

Tuomas Rasanen discovered that NBD incorrectly handled signals. A remote
attacker could use this issue to cause NBD to crash, resulting in a denial
of service. (CVE-2015-0847)");

  script_tag(name:"affected", value:"'nbd' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
