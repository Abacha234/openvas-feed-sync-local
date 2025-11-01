# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702898");
  script_cve_id("CVE-2014-1947", "CVE-2014-1958", "CVE-2014-2030");
  script_tag(name:"creation_date", value:"2014-04-08 22:00:00 +0000 (Tue, 08 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-11 15:18:00 +0000 (Tue, 11 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-2898)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2898");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2898");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-2898 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several buffer overflows were found in Imagemagick, a suite of image manipulation programs. Processing malformed PSD files could lead to the execution of arbitrary code.

For the oldstable distribution (squeeze), these problems have been fixed in version 8:6.6.0.4-3+squeeze4.

For the stable distribution (wheezy), these problems have been fixed in version 8:6.7.7.10-5+deb7u3.

For the testing distribution (jessie), these problems have been fixed in version 8:6.7.7.10+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 8:6.7.7.10+dfsg-1.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);