# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67831");
  script_cve_id("CVE-2010-2547");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2076");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2076");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg2' package(s) announced via the DSA-2076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GnuPG 2 uses a freed pointer when verifying a signature or importing a certificate with many Subject Alternate Names, potentially leading to arbitrary code execution.

For the stable distribution (lenny), this problem has been fixed in version 2.0.9-3.1+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 2.0.14-2.

GnuPG 1 (in the gnupg package) is not affected by this problem.

We recommend that you upgrade your gnupg2 packages.");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);