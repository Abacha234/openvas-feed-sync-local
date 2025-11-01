# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702989");
  script_cve_id("CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"creation_date", value:"2014-07-23 22:00:00 +0000 (Wed, 23 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2989)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2989");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2989");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-2989 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were found in the Apache HTTP server.

CVE-2014-0118

The DEFLATE input filter (inflates request bodies) in mod_deflate allows remote attackers to cause a denial of service (resource consumption) via crafted request data that decompresses to a much larger size.

CVE-2014-0226

A race condition was found in mod_status. An attacker able to access a public server status page on a server could send carefully crafted requests which could lead to a heap buffer overflow, causing denial of service, disclosure of sensitive information, or potentially the execution of arbitrary code.

CVE-2014-0231

A flaw was found in mod_cgid. If a server using mod_cgid hosted CGI scripts which did not consume standard input, a remote attacker could cause child processes to hang indefinitely, leading to denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 2.2.22-13+deb7u3.

For the testing distribution (jessie), these problems will be fixed in version 2.4.10-1.

For the unstable distribution (sid), these problems have been fixed in version 2.4.10-1.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);