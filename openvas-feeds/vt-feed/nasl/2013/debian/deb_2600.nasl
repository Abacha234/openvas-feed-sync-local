# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702600");
  script_cve_id("CVE-2012-5519");
  script_tag(name:"creation_date", value:"2013-01-05 23:00:00 +0000 (Sat, 05 Jan 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2600)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2600");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2600");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-2600 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that users of the CUPS printing system who are part of the lpadmin group could modify several configuration parameters with security impact. Specifically, this allows an attacker to read or write arbitrary files as root which can be used to elevate privileges.

This update splits the configuration file /etc/cups/cupsd.conf into two files: cupsd.conf and cups-files.conf. While the first stays configurable via the web interface, the latter can only be configured by the root user. Please see the updated documentation that comes with the new package for more information on these files.

For the stable distribution (squeeze), this problem has been fixed in version 1.4.4-7+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in version 1.5.3-2.7.

For the unstable distribution (sid), this problem has been fixed in version 1.5.3-2.7.

We recommend that you upgrade your cups packages.");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);