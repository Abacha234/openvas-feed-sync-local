# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704122");
  script_cve_id("CVE-2018-1000024", "CVE-2018-1000027");
  script_tag(name:"creation_date", value:"2018-02-22 23:00:00 +0000 (Thu, 22 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 16:15:00 +0000 (Wed, 17 Jul 2019)");

  script_name("Debian: Security Advisory (DSA-4122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4122");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4122");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/squid3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DSA-4122 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Squid3, a fully featured web proxy cache. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2018-1000024

Louis Dion-Marcil discovered that Squid does not properly handle processing of certain ESI responses. A remote server delivering certain ESI response syntax can take advantage of this flaw to cause a denial of service for all clients accessing the Squid service. This problem is limited to the Squid custom ESI parser.


CVE-2018-1000027

Louis Dion-Marcil discovered that Squid is prone to a denial of service vulnerability when processing ESI responses or downloading intermediate CA certificates. A remote attacker can take advantage of this flaw to cause a denial of service for all clients accessing the Squid service.


For the oldstable distribution (jessie), these problems have been fixed in version 3.4.8-6+deb8u5.

For the stable distribution (stretch), these problems have been fixed in version 3.5.23-5+deb9u1.

We recommend that you upgrade your squid3 packages.

For the detailed security status of squid3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);