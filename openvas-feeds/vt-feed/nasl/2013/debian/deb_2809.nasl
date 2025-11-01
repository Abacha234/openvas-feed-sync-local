# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702809");
  script_cve_id("CVE-2013-1821", "CVE-2013-4073", "CVE-2013-4164");
  script_tag(name:"creation_date", value:"2013-12-03 23:00:00 +0000 (Tue, 03 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2809)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2809");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2809");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.8' package(s) announced via the DSA-2809 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the Ruby language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1821

Ben Murphy discovered that unrestricted entity expansion in REXML can lead to a Denial of Service by consuming all host memory.

CVE-2013-4073

William (B.J.) Snow Orvis discovered a vulnerability in the hostname checking in Ruby's SSL client that could allow man-in-the-middle attackers to spoof SSL servers via a crafted certificate issued by a trusted certification authority.

CVE-2013-4164

Charlie Somerville discovered that Ruby incorrectly handled floating point number conversion. If an application using Ruby accepted untrusted input strings and converted them to floating point numbers, an attacker able to provide such input could cause the application to crash or, possibly, execute arbitrary code with the privileges of the application.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.8.7.302-2squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 1.8.7.358-7.1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1.8.7.358-9.

We recommend that you upgrade your ruby1.8 packages.");

  script_tag(name:"affected", value:"'ruby1.8' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);