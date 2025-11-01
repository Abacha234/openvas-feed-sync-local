# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703113");
  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141");
  script_tag(name:"creation_date", value:"2014-12-27 23:00:00 +0000 (Sat, 27 Dec 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 21:26:00 +0000 (Wed, 05 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-3113)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3113");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3113");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unzip' package(s) announced via the DSA-3113 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michele Spagnuolo of the Google Security Team discovered that unzip, an extraction utility for archives compressed in .zip format, is affected by heap-based buffer overflows within the CRC32 verification function (CVE-2014-8139), the test_compr_eb() function (CVE-2014-8140) and the getZip64Data() function (CVE-2014-8141), which may lead to the execution of arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 6.0-8+deb7u1.

For the upcoming stable distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 6.0-13.

We recommend that you upgrade your unzip packages.");

  script_tag(name:"affected", value:"'unzip' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);