# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64443");
  script_cve_id("CVE-2009-1890", "CVE-2009-1891");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-802-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-802-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that mod_proxy_http did not properly handle a large
amount of streamed data when used as a reverse proxy. A remote attacker
could exploit this and cause a denial of service via memory resource
consumption. This issue affected Ubuntu 8.04 LTS, 8.10 and 9.04.
(CVE-2009-1890)

It was discovered that mod_deflate did not abort compressing large files
when the connection was closed. A remote attacker could exploit this and
cause a denial of service via CPU resource consumption. (CVE-2009-1891)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
