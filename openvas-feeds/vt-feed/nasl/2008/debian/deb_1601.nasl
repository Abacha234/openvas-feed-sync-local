# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61247");
  script_cve_id("CVE-2007-1599", "CVE-2008-0664");
  script_tag(name:"creation_date", value:"2008-07-15 00:29:31 +0000 (Tue, 15 Jul 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1601)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1601");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1601");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-1601 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Wordpress, the weblog manager. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1599

WordPress allows remote attackers to redirect authenticated users to other websites and potentially obtain sensitive information.

CVE-2008-0664

The XML-RPC implementation, when registration is enabled, allows remote attackers to edit posts of other blog users.

For the stable distribution (etch), these problems have been fixed in version 2.0.10-1etch3.

For the unstable distribution (sid), these problems have been fixed in version 2.3.3-1.

We recommend that you upgrade your wordpress package.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);