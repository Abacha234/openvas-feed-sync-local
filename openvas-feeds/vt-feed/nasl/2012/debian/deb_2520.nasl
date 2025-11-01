# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71497");
  script_cve_id("CVE-2012-2665");
  script_tag(name:"creation_date", value:"2012-08-10 07:20:25 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2520)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2520");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2520");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-2520 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timo Warns from PRE-CERT discovered multiple heap-based buffer overflows in OpenOffice.org, an office productivity suite. The issues lies in the XML manifest encryption tag parsing code. Using specially crafted files, an attacker can cause application crash and could cause arbitrary code execution.

For the stable distribution (squeeze), this problem has been fixed in version 1:3.2.1-11+squeeze7.

openoffice.org package has been replaced by libreoffice in testing (wheezy) and unstable (sid) distributions.

For the testing distribution (wheezy), this problem has been fixed in version 1:3.5.4-7.

For the unstable distribution (sid), this problem has been fixed in version 1:3.5.4-7.

We recommend that you upgrade your openoffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);