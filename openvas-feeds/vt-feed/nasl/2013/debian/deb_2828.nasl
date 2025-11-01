# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702828");
  script_cve_id("CVE-2013-6385", "CVE-2013-6386");
  script_tag(name:"creation_date", value:"2013-12-27 23:00:00 +0000 (Fri, 27 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2828)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2828");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2828");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal6' package(s) announced via the DSA-2828 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Drupal, a fully-featured content management framework: vulnerabilities due to optimistic cross-site request forgery protection, insecure pseudo random number generation, code execution and incorrect security token validation.

In order to avoid the remote code execution vulnerability, it is recommended to create a .htaccess file (or an equivalent configuration directive in case you are not using Apache to serve your Drupal sites) in each of your sites' files directories (both public and private, in case you have both configured).

Please refer to the NEWS file provided with this update and the upstream advisory at drupal.org/SA-CORE-2013-003 for further information.

For the oldstable distribution (squeeze), these problems have been fixed in version 6.29-1.

We recommend that you upgrade your drupal6 packages.");

  script_tag(name:"affected", value:"'drupal6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);