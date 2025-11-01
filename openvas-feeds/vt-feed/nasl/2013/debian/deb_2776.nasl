# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702776");
  script_cve_id("CVE-2012-0825", "CVE-2012-0826", "CVE-2012-5651", "CVE-2012-5652", "CVE-2012-5653", "CVE-2013-0244", "CVE-2013-0245");
  script_tag(name:"creation_date", value:"2013-10-10 22:00:00 +0000 (Thu, 10 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2776)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2776");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2776");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal6' package(s) announced via the DSA-2776 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been been fixed in the Drupal content management framework, resulting in information disclosure, insufficient validation, cross-site scripting and cross-site request forgery.

For the oldstable distribution (squeeze), these problems have been fixed in version 6.28-1.

For the stable distribution (wheezy), these problems have already been fixed in the drupal7 package.

For the unstable distribution (sid), these problems have already been fixed in the drupal7 package.

We recommend that you upgrade your drupal6 packages.");

  script_tag(name:"affected", value:"'drupal6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);