# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840373");
  script_cve_id("CVE-2009-4022", "CVE-2010-0097", "CVE-2010-0290");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:05 +0000 (Fri, 22 Jan 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-888-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-888-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-888-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-888-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Bind would incorrectly cache bogus NXDOMAIN
responses. When DNSSEC validation is in use, a remote attacker could
exploit this to cause a denial of service, and possibly poison DNS caches.
(CVE-2010-0097)

USN-865-1 provided updated Bind packages to fix a security vulnerability.
The upstream security patch to fix CVE-2009-4022 was incomplete and
CVE-2010-0290 was assigned to the issue. This update corrects the problem.
Original advisory details:

 Michael Sinatra discovered that Bind did not correctly validate certain
 records added to its cache. When DNSSEC validation is in use, a remote
 attacker could exploit this to spoof DNS entries and poison DNS caches.
 Among other things, this could lead to misdirected email and web traffic.");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
