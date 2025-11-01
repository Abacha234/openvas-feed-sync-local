# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842104");
  script_cve_id("CVE-2013-7423", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1473");
  script_tag(name:"creation_date", value:"2015-02-27 04:42:47 +0000 (Fri, 27 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2519-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2519-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2519-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-2519-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Arnaud Le Blanc discovered that the GNU C Library incorrectly handled file
descriptors when resolving DNS queries under high load. This may cause a
denial of service in other applications, or an information leak. This issue
only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2013-7423)

It was discovered that the GNU C Library incorrectly handled receiving a
positive answer while processing the network name when performing DNS
resolution. A remote attacker could use this issue to cause the GNU C
Library to hang, resulting in a denial of service. (CVE-2014-9402)

Joseph Myers discovered that the GNU C Library wscanf function incorrectly
handled memory. A remote attacker could possibly use this issue to cause
the GNU C Library to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS, Ubuntu
14.04 LTS and Ubuntu 14.10. (CVE-2015-1472, CVE-2015-1473)");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
