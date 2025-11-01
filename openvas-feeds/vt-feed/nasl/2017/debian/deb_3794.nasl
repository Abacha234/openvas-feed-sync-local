# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703794");
  script_cve_id("CVE-2017-6188");
  script_tag(name:"creation_date", value:"2017-02-24 23:00:00 +0000 (Fri, 24 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-27 14:20:00 +0000 (Wed, 27 May 2020)");

  script_name("Debian: Security Advisory (DSA-3794)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3794");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3794");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'munin' package(s) announced via the DSA-3794 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stevie Trujillo discovered a local file write vulnerability in munin, a network-wide graphing framework, when CGI graphs are enabled. GET parameters are not properly handled, allowing to inject options into munin-cgi-graph and overwriting any file accessible by the user running the cgi-process.

For the stable distribution (jessie), this problem has been fixed in version 2.0.25-1+deb8u1.

We recommend that you upgrade your munin packages.");

  script_tag(name:"affected", value:"'munin' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);