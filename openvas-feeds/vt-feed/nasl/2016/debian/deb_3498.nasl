# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703498");
  script_cve_id("CVE-2016-3162", "CVE-2016-3163", "CVE-2016-3164", "CVE-2016-3168", "CVE-2016-3169", "CVE-2016-3170");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:50 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 14:33:00 +0000 (Thu, 14 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3498)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3498");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3498");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-3498 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been found in the Drupal content management framework. For additional information, please refer to the upstream advisory at

For the oldstable distribution (wheezy), this problem has been fixed in version 7.14-2+deb7u12.

For the stable distribution (jessie), this problem has been fixed in version 7.32-1+deb8u6.

For the unstable distribution (sid), this problem has been fixed in version 7.43-1.

We recommend that you upgrade your drupal7 packages.");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);