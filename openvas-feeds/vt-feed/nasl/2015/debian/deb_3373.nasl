# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703373");
  script_cve_id("CVE-2015-4716", "CVE-2015-4717", "CVE-2015-4718", "CVE-2015-5953", "CVE-2015-5954", "CVE-2015-6500", "CVE-2015-6670", "CVE-2015-7699");
  script_tag(name:"creation_date", value:"2015-10-17 22:00:00 +0000 (Sat, 17 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3373");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3373");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'owncloud' package(s) announced via the DSA-3373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in ownCloud, a cloud storage web service for files, music, contacts, calendars and many more. These flaws may lead to the execution of arbitrary code, authorization bypass, information disclosure, cross-site scripting or denial of service.

For the stable distribution (jessie), these problems have been fixed in version 7.0.4+dfsg-4~deb8u3.

For the testing distribution (stretch), these problems have been fixed in version 7.0.10~dfsg-2 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in version 7.0.10~dfsg-2 or earlier versions.

We recommend that you upgrade your owncloud packages.");

  script_tag(name:"affected", value:"'owncloud' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);