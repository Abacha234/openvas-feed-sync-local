# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53635");
  script_cve_id("CVE-2003-0536");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-346");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-346");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpsysinfo' package(s) announced via the DSA-346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Albert Puigsech Galicia reported that phpsysinfo, a web-based program to display status information about the system, contains two vulnerabilities which could allow local files to be read, or arbitrary PHP code to be executed, under the privileges of the web server process (usually www-data). These vulnerabilities require access to a writable directory on the system in order to be exploited.

For the stable distribution (woody) this problem has been fixed in version 2.0-3woody1.

For the unstable distribution (sid) this problem will be fixed soon. See Debian bug #200543.

We recommend that you update your phpsysinfo package.");

  script_tag(name:"affected", value:"'phpsysinfo' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);