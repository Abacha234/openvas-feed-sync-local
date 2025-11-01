# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702742");
  script_cve_id("CVE-2013-4248");
  script_tag(name:"creation_date", value:"2013-08-25 22:00:00 +0000 (Sun, 25 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2742)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2742");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2742");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2742 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP, a general-purpose scripting language commonly used for web application development, did not properly process embedded NUL characters in the subjectAltName extension of X.509 certificates. Depending on the application and with insufficient CA-level checks, this could be abused for impersonating other users.

For the oldstable distribution (squeeze), this problem has been fixed in version 5.3.3-7+squeeze17.

For the stable distribution (wheezy), this problem has been fixed in version 5.4.4-14+deb7u4.

For the unstable distribution (sid), this problem has been fixed in version 5.5.3+dfsg-1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);