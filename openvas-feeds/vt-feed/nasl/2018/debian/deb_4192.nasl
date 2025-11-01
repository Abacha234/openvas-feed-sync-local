# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704192");
  script_cve_id("CVE-2017-8372", "CVE-2017-8373", "CVE-2017-8374");
  script_tag(name:"creation_date", value:"2018-05-03 22:00:00 +0000 (Thu, 03 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-20 01:29:00 +0000 (Sun, 20 May 2018)");

  script_name("Debian: Security Advisory (DSA-4192)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4192");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4192");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libmad");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmad' package(s) announced via the DSA-4192 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in MAD, an MPEG audio decoder library, which could result in denial of service if a malformed audio file is processed.

For the oldstable distribution (jessie), these problems have been fixed in version 0.15.1b-8+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 0.15.1b-8+deb9u1.

We recommend that you upgrade your libmad packages.

For the detailed security status of libmad please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libmad' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);