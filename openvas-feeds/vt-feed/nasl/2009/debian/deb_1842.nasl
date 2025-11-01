# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64481");
  script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1842)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1842");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1842");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openexr' package(s) announced via the DSA-1842 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the OpenEXR image library, which can lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1720

Drew Yao discovered integer overflows in the preview and compression code.

CVE-2009-1721

Drew Yao discovered that an uninitialised pointer could be freed in the decompression code.

CVE-2009-1722

A buffer overflow was discovered in the compression code.

For the old stable distribution (etch), these problems have been fixed in version 1.2.2-4.3+etch2.

For the stable distribution (lenny), these problems have been fixed in version 1.6.1-3+lenny3.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openexr packages.");

  script_tag(name:"affected", value:"'openexr' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);