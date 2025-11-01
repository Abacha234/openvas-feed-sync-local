# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60430");
  script_cve_id("CVE-2007-6595", "CVE-2008-0318");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1497)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1497");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1497");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1497 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Clam anti-virus toolkit, which may lead to the execution of arbitrary code or local denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6595

It was discovered that temporary files are created insecurely, which may result in local denial of service by overwriting files.

CVE-2008-0318

Silvio Cesare discovered an integer overflow in the parser for PE headers.

The version of clamav in the old stable distribution (sarge) is no longer supported with security updates.

For the stable distribution (etch), these problems have been fixed in version 0.90.1dfsg-3etch10. In addition to these fixes, this update also incorporates changes from the upcoming point release of the stable distribution (non-free RAR handling code was removed).

We recommend that you upgrade your clamav packages.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);