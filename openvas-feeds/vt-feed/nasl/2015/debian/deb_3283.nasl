# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703283");
  script_cve_id("CVE-2015-1158", "CVE-2015-1159");
  script_tag(name:"creation_date", value:"2015-06-08 22:00:00 +0000 (Mon, 08 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3283");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3283");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-3283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CUPS, the Common UNIX Printing System, is vulnerable to a remotely triggerable privilege escalation via cross-site scripting and bad print job submission used to replace cupsd.conf on the CUPS server.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.5.3-5+deb7u6.

For the stable distribution (jessie), these problems have been fixed in version 1.7.5-11+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 1.7.5-12.

We recommend that you upgrade your cups packages.");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);