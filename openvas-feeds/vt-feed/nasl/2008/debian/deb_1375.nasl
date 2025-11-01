# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58597");
  script_cve_id("CVE-2007-2834");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1375)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1375");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1375");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-1375 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap overflow vulnerability has been discovered in the TIFF parsing code of the OpenOffice.org suite. The parser uses untrusted values from the TIFF file to calculate the number of bytes of memory to allocate. A specially crafted TIFF image could trigger an integer overflow and subsequently a buffer overflow that could cause the execution of arbitrary code.

For the old stable distribution (sarge) this problem has been fixed in version 1.1.3-9sarge8.

For the stable distribution (etch) this problem has been fixed in version 2.0.4.dfsg.2-7etch2.

For the unstable distribution (sid) this problem has been fixed in version 2.2.1-9.

For the experimental distribution this problem has been fixed in version 2.3.0~src680m224-1.

We recommend that you upgrade your openoffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);