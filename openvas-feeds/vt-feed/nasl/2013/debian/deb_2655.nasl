# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702655");
  script_cve_id("CVE-2011-2932", "CVE-2012-3464", "CVE-2012-3465", "CVE-2013-1854", "CVE-2013-1855", "CVE-2013-1857");
  script_tag(name:"creation_date", value:"2013-03-27 23:00:00 +0000 (Wed, 27 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2655)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2655");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2655");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DSA-2655 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several cross-site-scripting and denial of service vulnerabilities were discovered in Ruby on Rails, a Ruby framework for web application development.

For the stable distribution (squeeze), these problems have been fixed in version 2.3.5-1.2+squeeze8.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in the version 3.2.6-5 of ruby-activerecord-3.2, version 2.3.14-6 of ruby-activerecord-2.3, version 2.3.14-7 of ruby-activesupport-2.3, version 3.2.6-6 of ruby-actionpack-3.2 and in version 2.3.14-5 of ruby-actionpack-2.3.

We recommend that you upgrade your rails packages.");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);