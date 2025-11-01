# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702815");
  script_cve_id("CVE-2013-6048", "CVE-2013-6359");
  script_tag(name:"creation_date", value:"2013-12-08 23:00:00 +0000 (Sun, 08 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2815)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2815");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2815");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'munin' package(s) announced via the DSA-2815 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christoph Biedl discovered two denial of service vulnerabilities in munin, a network-wide graphing framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-6048

The Munin::Master::Node module of munin does not properly validate certain data a node sends. A malicious node might exploit this to drive the munin-html process into an infinite loop with memory exhaustion on the munin master.

CVE-2013-6359

A malicious node, with a plugin enabled using multigraph as a multigraph service name, can abort data collection for the entire node the plugin runs on.

For the stable distribution (wheezy), these problems have been fixed in version 2.0.6-4+deb7u2.

For the testing distribution (jessie), these problems have been fixed in version 2.0.18-1.

For the unstable distribution (sid), these problems have been fixed in version 2.0.18-1.

We recommend that you upgrade your munin packages.");

  script_tag(name:"affected", value:"'munin' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);