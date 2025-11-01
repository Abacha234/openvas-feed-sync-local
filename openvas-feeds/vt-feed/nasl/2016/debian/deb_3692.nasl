# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703692");
  script_cve_id("CVE-2015-3885", "CVE-2016-5684");
  script_tag(name:"creation_date", value:"2016-10-12 22:00:00 +0000 (Wed, 12 Oct 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-28 20:29:00 +0000 (Thu, 28 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3692)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3692");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3692");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freeimage' package(s) announced via the DSA-3692 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the FreeImage multimedia library, which might result in denial of service or the execution of arbitrary code if a malformed XMP or RAW image is processed.

For the stable distribution (jessie), these problems have been fixed in version 3.15.4-4.2+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 3.17.0+ds1-3.

For the unstable distribution (sid), these problems have been fixed in version 3.17.0+ds1-3.

We recommend that you upgrade your freeimage packages.");

  script_tag(name:"affected", value:"'freeimage' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);