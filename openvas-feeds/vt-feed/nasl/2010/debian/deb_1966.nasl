# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66657");
  script_cve_id("CVE-2009-3237", "CVE-2009-3701", "CVE-2009-4363");
  script_tag(name:"creation_date", value:"2010-01-11 22:48:26 +0000 (Mon, 11 Jan 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1966)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1966");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1966");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'horde3' package(s) announced via the DSA-1966 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in horde3, the horde web application framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3237

It has been discovered that horde3 is prone to cross-site scripting attacks via crafted number preferences or inline MIME text parts when using text/plain as MIME type. For lenny this issue was already fixed, but as an additional security precaution, the display of inline text was disabled in the configuration file.

CVE-2009-3701

It has been discovered that the horde3 administration interface is prone to cross-site scripting attacks due to the use of the PHP_SELF variable. This issue can only be exploited by authenticated administrators.

CVE-2009-4363

It has been discovered that horde3 is prone to several cross-site scripting attacks via crafted data:text/html values in HTML messages.

For the stable distribution (lenny), these problems have been fixed in version 3.2.2+debian0-2+lenny2.

For the oldstable distribution (etch), these problems have been fixed in version 3.1.3-4etch7.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 3.3.6+debian0-1.

We recommend that you upgrade your horde3 packages.");

  script_tag(name:"affected", value:"'horde3' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);