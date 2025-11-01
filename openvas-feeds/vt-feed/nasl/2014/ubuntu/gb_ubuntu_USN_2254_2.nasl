# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841875");
  script_cve_id("CVE-2014-0185", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-4049");
  script_tag(name:"creation_date", value:"2014-07-01 16:52:18 +0000 (Tue, 01 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2254-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2254-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2254-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1334337");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-2254-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2254-1 fixed vulnerabilities in PHP. The fix for CVE-2014-0185
further restricted the permissions on the PHP FastCGI Process Manager (FPM)
UNIX socket. This update grants socket access to the www-data user and
group so installations and documentation relying on the previous socket
permissions will continue to function.

Original advisory details:

 Christian Hoffmann discovered that the PHP FastCGI Process Manager (FPM)
 set incorrect permissions on the UNIX socket. A local attacker could use
 this issue to possibly elevate their privileges. This issue only affected
 Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS. (CVE-2014-0185)

 Francisco Alonso discovered that the PHP Fileinfo component incorrectly
 handled certain CDF documents. A remote attacker could use this issue to
 cause PHP to hang or crash, resulting in a denial of service.
 (CVE-2014-0237, CVE-2014-0238)

 Stefan Esser discovered that PHP incorrectly handled DNS TXT records. A
 remote attacker could use this issue to cause PHP to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2014-4049)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
