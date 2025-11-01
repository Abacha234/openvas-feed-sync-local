# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844682");
  script_cve_id("CVE-2019-16869", "CVE-2019-20444", "CVE-2019-20445", "CVE-2020-11612", "CVE-2020-7238");
  script_tag(name:"creation_date", value:"2020-10-28 04:01:08 +0000 (Wed, 28 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 10:15:00 +0000 (Mon, 26 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4600-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4600-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4600-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty' package(s) announced via the USN-4600-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4600-1 fixed multiple vulnerabilities in Netty 3.9. This update provides
the corresponding fixes for CVE-2019-20444, CVE-2019-20445 for Netty.

Also it was discovered that Netty allow for unbounded memory allocation. A
remote attacker could send a large stream to the Netty server causing it to
crash (denial of service). (CVE-2020-11612)

Original advisory details:

 It was discovered that Netty had HTTP request smuggling vulnerabilities. A
 remote attacker could used it to extract sensitive information. (CVE-2019-16869,
 CVE-2019-20444, CVE-2019-20445, CVE-2020-7238)");

  script_tag(name:"affected", value:"'netty' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
