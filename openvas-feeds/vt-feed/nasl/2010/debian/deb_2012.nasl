# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67036");
  script_cve_id("CVE-2009-3725", "CVE-2010-0622");
  script_tag(name:"creation_date", value:"2010-03-16 16:25:39 +0000 (Tue, 16 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2012");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2012");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3725

Philipp Reisner reported an issue in the connector subsystem which allows unprivileged users to send netlink packets. This allows local users to manipulate settings for uvesafb devices which are normally reserved for privileged users.

CVE-2010-0622

Jerome Marchand reported an issue in the futex subsystem that allows a local user to force an invalid futex state which results in a denial of service (oops).

This update also includes fixes for regressions introduced by previous updates. See the referenced Debian bug pages for details.

For the stable distribution (lenny), this problem has been fixed in version 2.6.26-21lenny4.

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 5.0 (lenny)

user-mode-linux 2.6.26-1um-2+21lenny4");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);