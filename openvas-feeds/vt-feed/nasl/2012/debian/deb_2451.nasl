# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71255");
  script_cve_id("CVE-2012-1906", "CVE-2012-1986", "CVE-2012-1987", "CVE-2012-1988");
  script_tag(name:"creation_date", value:"2012-04-30 11:56:51 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2451)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2451");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2451");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'puppet' package(s) announced via the DSA-2451 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Puppet, a centralized configuration management system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-1906

Puppet is using predictable temporary file names when downloading Mac OS X package files. This allows a local attacker to either overwrite arbitrary files on the system or to install an arbitrary package.

CVE-2012-1986

When handling requests for a file from a remote filebucket, Puppet can be tricked into overwriting its defined location for filebucket storage. This allows an authorized attacker with access to the Puppet master to read arbitrary files.

CVE-2012-1987

Puppet is incorrectly handling filebucket store requests. This allows an attacker to perform denial of service attacks against Puppet by resource exhaustion.

CVE-2012-1988

Puppet is incorrectly handling filebucket requests. This allows an attacker with access to the certificate on the agent and an unprivileged account on Puppet master to execute arbitrary code via crafted file path names and making a filebucket request.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.2-5+squeeze5.

For the testing distribution (wheezy), this problem has been fixed in version 2.7.13-1.

For the unstable distribution (sid), this problem has been fixed in version 2.7.13-1.

We recommend that you upgrade your puppet packages.");

  script_tag(name:"affected", value:"'puppet' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);