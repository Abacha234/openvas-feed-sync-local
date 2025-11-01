# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53119");
  script_cve_id("CVE-2004-0016", "CVE-2004-0017");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-419");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-419");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The authors of phpgroupware, a web based groupware system written in PHP, discovered several vulnerabilities. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2004-0016

In the 'calendar' module, 'save extension' was not enforced for holiday files. As a result, server-side php scripts may be placed in directories that then could be accessed remotely and cause the webserver to execute those. This was resolved by enforcing the extension '.txt' for holiday files.

CAN-2004-0017

Some SQL injection problems (non-escaping of values used in SQL strings) the 'calendar' and 'infolog' modules.

Additionally, the Debian maintainer adjusted the permissions on world writable directories that were accidentally created by former postinst during the installation.

For the stable distribution (woody) this problem has been fixed in version 0.9.14-0.RC3.2.woody3.

For the unstable distribution (sid) this problem has been fixed in version 0.9.14.007-4.

We recommend that you upgrade your phpgroupware, phpgroupware-calendar and phpgroupware-infolog packages.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);