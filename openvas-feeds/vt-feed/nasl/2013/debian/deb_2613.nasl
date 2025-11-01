# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702613");
  script_cve_id("CVE-2013-0333");
  script_tag(name:"creation_date", value:"2013-01-28 23:00:00 +0000 (Mon, 28 Jan 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2613)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2613");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2613");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DSA-2613 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lawrence Pit discovered that Ruby on Rails, a web development framework, is vulnerable to a flaw in the parsing of JSON to YAML. Using a specially crafted payload attackers can trick the backend into decoding a subset of YAML.

The vulnerability has been addressed by removing the YAML backend and adding the OkJson backend.

For the stable distribution (squeeze), this problem has been fixed in version 2.3.5-1.2+squeeze6.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.3.14-6 of the ruby-activesupport-2.3 package.

The 3.2 version of rails as found in Debian wheezy and sid is not affected by the problem.

We recommend that you upgrade your rails packages.");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);