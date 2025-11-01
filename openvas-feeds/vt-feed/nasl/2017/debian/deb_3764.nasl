# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703764");
  script_cve_id("CVE-2016-2120", "CVE-2016-7068", "CVE-2016-7072", "CVE-2016-7073", "CVE-2016-7074");
  script_tag(name:"creation_date", value:"2017-01-12 23:00:00 +0000 (Thu, 12 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3764)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3764");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3764");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns' package(s) announced via the DSA-3764 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in pdns, an authoritative DNS server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-2120

Mathieu Lafon discovered that pdns does not properly validate records in zones. An authorized user can take advantage of this flaw to crash server by inserting a specially crafted record in a zone under their control and then sending a DNS query for that record.

CVE-2016-7068

Florian Heinz and Martin Kluge reported that pdns parses all records present in a query regardless of whether they are needed or even legitimate, allowing a remote, unauthenticated attacker to cause an abnormal CPU usage load on the pdns server, resulting in a partial denial of service if the system becomes overloaded.

CVE-2016-7072

Mongo discovered that the webserver in pdns is susceptible to a denial-of-service vulnerability, allowing a remote, unauthenticated attacker to cause a denial of service by opening a large number of TCP connections to the web server.

CVE-2016-7073 / CVE-2016-7074 Mongo discovered that pdns does not sufficiently validate TSIG signatures, allowing an attacker in position of man-in-the-middle to alter the content of an AXFR.

For the stable distribution (jessie), these problems have been fixed in version 3.4.1-4+deb8u7.

For the unstable distribution (sid), these problems have been fixed in version 4.0.2-1.

We recommend that you upgrade your pdns packages.");

  script_tag(name:"affected", value:"'pdns' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);