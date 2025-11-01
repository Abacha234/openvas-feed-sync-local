# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844520");
  script_cve_id("CVE-2019-12520", "CVE-2019-12523", "CVE-2019-12524", "CVE-2019-18676");
  script_tag(name:"creation_date", value:"2020-08-04 03:00:42 +0000 (Tue, 04 Aug 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-09 16:55:00 +0000 (Tue, 09 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-4446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4446-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4446-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-4446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeriko One discovered that Squid incorrectly handled caching certain
requests. A remote attacker could possibly use this issue to perform
cache-injection attacks or gain access to reverse proxy features such as
ESI. (CVE-2019-12520)

Jeriko One and Kristoffer Danielsson discovered that Squid incorrectly
handled certain URN requests. A remote attacker could possibly use this
issue to bypass access checks. (CVE-2019-12523)

Jeriko One discovered that Squid incorrectly handled URL decoding. A remote
attacker could possibly use this issue to bypass certain rule checks.
(CVE-2019-12524)

Jeriko One and Kristoffer Danielsson discovered that Squid incorrectly
handled input validation. A remote attacker could use this issue to cause
Squid to crash, resulting in a denial of service. (CVE-2019-18676)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
