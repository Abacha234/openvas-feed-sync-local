# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60794");
  script_cve_id("CVE-2007-5745", "CVE-2007-5746", "CVE-2007-5747", "CVE-2008-0320");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1547)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1547");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1547");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-1547 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in OpenOffice.org, the free office suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5745, CVE-2007-5747 Several bugs have been discovered in the way OpenOffice.org parses Quattro Pro files that may lead to a overflow in the heap potentially leading to the execution of arbitrary code.

CVE-2007-5746

Specially crafted EMF files can trigger a buffer overflow in the heap that may lead to the execution of arbitrary code.

CVE-2008-0320

A bug has been discovered in the processing of OLE files that can cause a buffer overflow in the heap potentially leading to the execution of arbitrary code.

Recently reported problems in the ICU library are fixed in separate libicu packages with DSA 1511 against which OpenOffice.org is linked.

For the old stable distribution (sarge) these problems have been fixed in version 1.1.3-9sarge9.

For the stable distribution (etch) these problems have been fixed in version 2.0.4.dfsg.2-7etch5.

For the testing (lenny) and unstable (sid) distributions these problems have been fixed in version 2.4.0~ooh680m5-1.

We recommend that you upgrade your openoffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);