# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67031");
  script_cve_id("CVE-2010-0393");
  script_tag(name:"creation_date", value:"2010-03-16 16:25:39 +0000 (Tue, 16 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2007");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2007");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-2007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ronald Volgers discovered that the lppasswd component of the cups suite, the Common UNIX Printing System, is vulnerable to format string attacks due to insecure use of the LOCALEDIR environment variable. An attacker can abuse this behaviour to execute arbitrary code via crafted localization files and triggering calls to _cupsLangprintf(). This works as the lppasswd binary happens to be installed with setuid 0 permissions.

For the stable distribution (lenny), this problem has been fixed in version 1.3.8-1+lenny8.

For the testing distribution (squeeze) this problem will be fixed soon.

For the unstable distribution (sid) this problem has been fixed in version 1.4.2-9.1.

We recommend that you upgrade your cups packages.");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);