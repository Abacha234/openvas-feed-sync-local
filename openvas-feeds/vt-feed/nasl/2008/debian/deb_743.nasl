# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54190");
  script_cve_id("CVE-2005-1545", "CVE-2005-1546");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-743");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-743");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ht' package(s) announced via the DSA-743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in ht, a viewer, editor and analyser for various executables, that may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-1545

Tavis Ormandy of the Gentoo Linux Security Team discovered an integer overflow in the ELF parser.

CAN-2005-1546

The authors have discovered a buffer overflow in the PE parser.

For the old stable distribution (woody) these problems have been fixed in version 0.5.0-1woody4. For the HP Precision architecture, you are advised not to use this package anymore since we cannot provide updated packages as it doesn't compile anymore.

For the stable distribution (sarge) these problems have been fixed in version 0.8.0-2sarge4.

For the unstable distribution (sid) these problems have been fixed in version 0.8.0-3.

We recommend that you upgrade your ht package.");

  script_tag(name:"affected", value:"'ht' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);