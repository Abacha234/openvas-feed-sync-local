# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68663");
  script_cve_id("CVE-2010-3767", "CVE-2010-3769", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3778");
  script_tag(name:"creation_date", value:"2011-01-24 16:55:59 +0000 (Mon, 24 Jan 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2132)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2132");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2132");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-2132 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.19-7.

For the upcoming stable version (squeeze) and the unstable distribution (sid), these problems have been fixed in version 3.5.15-1.

For the experimental distribution, these problems have been fixed in version 3.6.13-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);