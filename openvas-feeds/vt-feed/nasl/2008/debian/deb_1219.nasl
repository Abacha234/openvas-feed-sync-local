# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57654");
  script_cve_id("CVE-2005-3011", "CVE-2006-4810");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1219");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1219");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'texinfo' package(s) announced via the DSA-1219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the GNU texinfo package, a documentation system for on-line information and printed output.

CVE-2005-3011

Handling of temporary files is performed in an insecure manner, allowing an attacker to overwrite any file writable by the victim.

CVE-2006-4810

A buffer overflow in util/texindex.c could allow an attacker to execute arbitrary code with the victim's access rights by inducing the victim to run texindex or tex2dvi on a specially crafted texinfo file.

For the stable distribution (sarge), these problems have been fixed in version 4.7-2.2sarge2. Note that binary packages for the mipsel architecture are not currently available due to technical problems with the build host. These packages will be made available as soon as possible.

For unstable (sid) and the upcoming stable release (etch), these problems have been fixed in version 4.8.dfsg.1-4.

We recommend that you upgrade your texinfo package.");

  script_tag(name:"affected", value:"'texinfo' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);