# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841054");
  script_cve_id("CVE-2012-1457", "CVE-2012-1458", "CVE-2012-1459");
  script_tag(name:"creation_date", value:"2012-06-22 04:58:29 +0000 (Fri, 22 Jun 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1482-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1482-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1482-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1015337");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the USN-1482-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1482-1 fixed vulnerabilities in ClamAV. The updated packages could fail
to install in certain situations. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that ClamAV incorrectly handled certain malformed TAR
 archives. A remote attacker could create a specially-crafted TAR file
 containing malware that could escape being detected. (CVE-2012-1457,
 CVE-2012-1459)

 It was discovered that ClamAV incorrectly handled certain malformed CHM
 files. A remote attacker could create a specially-crafted CHM file
 containing malware that could escape being detected. (CVE-2012-1458)");

  script_tag(name:"affected", value:"'clamav' package(s) on Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
