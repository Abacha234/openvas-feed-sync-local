# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844371");
  script_cve_id("CVE-2019-12387", "CVE-2019-12855", "CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515", "CVE-2020-10108", "CVE-2020-10109");
  script_tag(name:"creation_date", value:"2020-03-20 04:00:21 +0000 (Fri, 20 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-22 17:22:00 +0000 (Thu, 22 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4308-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4308-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'twisted' package(s) announced via the USN-4308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"it was discovered that Twisted incorrectly validated or sanitized certain
URIs or HTTP methods. A remote attacker could use this issue to inject
invalid characters and possibly perform header injection attacks.
(CVE-2019-12387)

It was discovered that Twisted incorrectly verified XMPP TLS certificates.
A remote attacker could possibly use this issue to perform a
machine-in-the-middle attack and obtain sensitive information. (CVE-2019-12855)

It was discovered that Twisted incorrectly handled HTTP/2 connections. A
remote attacker could possibly use this issue to cause Twisted to hang or
consume resources, leading to a denial of service. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2019-9512, CVE-2019-9514,
CVE-2019-9515)

Jake Miller and ZeddYu Lu discovered that Twisted incorrectly handled
certain content-length headers. A remote attacker could possibly use this
issue to perform HTTP request splitting attacks. (CVE-2020-10108,
CVE-2020-10109)");

  script_tag(name:"affected", value:"'twisted' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
