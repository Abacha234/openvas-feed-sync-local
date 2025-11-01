# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60365");
  script_cve_id("CVE-2008-0665", "CVE-2008-0666");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1492)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1492");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1492");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wml' package(s) announced via the DSA-1492 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Frank Lichtenheld and Nico Golde discovered that WML, an off-line HTML generation toolkit, creates insecure temporary files in the eperl and ipp backends and in the wmg.cgi script, which could lead to a local denial of service by overwriting files.

The old stable distribution (sarge) is not affected.

For the stable distribution (etch), these problems have been fixed in version 2.0.11-1etch1.

We recommend that you upgrade your wml packages.");

  script_tag(name:"affected", value:"'wml' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);