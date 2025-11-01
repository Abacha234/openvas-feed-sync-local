# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844920");
  script_cve_id("CVE-2021-1252", "CVE-2021-1404", "CVE-2021-1405");
  script_tag(name:"creation_date", value:"2021-05-05 03:01:06 +0000 (Wed, 05 May 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4918-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4918-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4918-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1926300");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the USN-4918-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4918-1 fixed vulnerabilities in ClamAV. The updated package could
fail to properly scan in some situations. This update fixes
the problem.

Original advisory details:

 It was discovered that ClamAV incorrectly handled parsing Excel documents.
 A remote attacker could possibly use this issue to cause ClamAV to hang,
 resulting in a denial of service. (CVE-2021-1252)

 It was discovered that ClamAV incorrectly handled parsing PDF documents. A
 remote attacker could possibly use this issue to cause ClamAV to crash,
 resulting in a denial of service. (CVE-2021-1404)

 It was discovered that ClamAV incorrectly handled parsing email. A remote
 attacker could possibly use this issue to cause ClamAV to crash, resulting
 in a denial of service. (CVE-2021-1405)");

  script_tag(name:"affected", value:"'clamav' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
