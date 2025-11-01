# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702585");
  script_cve_id("CVE-2012-5468");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2585)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2585");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2585");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bogofilter' package(s) announced via the DSA-2585 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow was discovered in bogofilter, a software package for classifying mail messages as spam or non-spam. Crafted mail messages with invalid base64 data could lead to heap corruption and, potentially, arbitrary code execution.

For the stable distribution (squeeze), this problem has been fixed in version 1.2.2-2+squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 1.2.2+dfsg1-2.

We recommend that you upgrade your bogofilter packages.");

  script_tag(name:"affected", value:"'bogofilter' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);