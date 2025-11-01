# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55191");
  script_cve_id("CVE-2005-1751", "CVE-2005-1921", "CVE-2005-2498");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-789)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-789");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-789");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php4' package(s) announced via the DSA-789 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been found in PHP4, the server-side, HTML-embedded scripting language. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-1751

Eric Romang discovered insecure temporary files in the shtool utility shipped with PHP that can exploited by a local attacker to overwrite arbitrary files. Only this vulnerability affects packages in oldstable.

CAN-2005-1921

GulfTech has discovered that PEAR XML_RPC is vulnerable to a remote PHP code execution vulnerability that may allow an attacker to compromise a vulnerable server.

CAN-2005-2498

Stefan Esser discovered another vulnerability in the XML-RPC libraries that allows injection of arbitrary PHP code into eval() statements.

For the old stable distribution (woody) these problems have been fixed in version 4.1.2-7.woody5.

For the stable distribution (sarge) these problems have been fixed in version 4.3.10-16.

For the unstable distribution (sid) these problems have been fixed in version 4.4.0-2.

We recommend that you upgrade your PHP packages.");

  script_tag(name:"affected", value:"'php4' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);