# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840387");
  script_cve_id("CVE-2009-2855", "CVE-2010-0308");
  script_tag(name:"creation_date", value:"2010-02-19 12:38:15 +0000 (Fri, 19 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-901-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-901-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-901-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the USN-901-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Squid incorrectly handled certain auth headers. A
remote attacker could exploit this with a specially-crafted auth header
and cause Squid to go into an infinite loop, resulting in a denial of
service. This issue only affected Ubuntu 8.10, 9.04 and 9.10.
(CVE-2009-2855)

It was discovered that Squid incorrectly handled certain DNS packets. A
remote attacker could exploit this with a specially-crafted DNS packet
and cause Squid to crash, resulting in a denial of service. (CVE-2010-0308)");

  script_tag(name:"affected", value:"'squid' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
