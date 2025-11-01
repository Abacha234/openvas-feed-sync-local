# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61904");
  script_cve_id("CVE-2008-4225", "CVE-2008-4226");
  script_tag(name:"creation_date", value:"2008-11-24 22:46:43 +0000 (Mon, 24 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1666)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1666");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1666");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-1666 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the GNOME XML library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4225

Drew Yao discovered that missing input sanitising in the xmlBufferResize() function may lead to an infinite loop, resulting in denial of service.

CVE-2008-4226

Drew Yao discovered that an integer overflow in the xmlSAX2Characters() function may lead to denial of service or the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 2.6.27.dfsg-6.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), these problems have been fixed in version 2.6.32.dfsg-5.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);