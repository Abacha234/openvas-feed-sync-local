# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703235");
  script_cve_id("CVE-2014-8873", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_tag(name:"creation_date", value:"2015-04-23 22:00:00 +0000 (Thu, 23 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3235");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3235");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-7' package(s) announced via the DSA-3235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Oracle Java platform, resulting in the execution of arbitrary code, breakouts of the Java sandbox, information disclosure or denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 7u79-2.5.5-1~deb7u1.

For the upcoming stable distribution (jessie), these problems will be fixed soon in version 7u79-2.5.5-1~deb8u1 (the update will be available shortly after the final jessie release).

For the unstable distribution (sid), these problems have been fixed in version 7u79-2.5.5-1.

We recommend that you upgrade your openjdk-7 packages.");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);