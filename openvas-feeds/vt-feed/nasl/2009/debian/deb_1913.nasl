# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66096");
  script_cve_id("CVE-2009-3165");
  script_tag(name:"creation_date", value:"2009-10-27 00:37:56 +0000 (Tue, 27 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1913)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1913");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1913");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bugzilla' package(s) announced via the DSA-1913 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Kanat-Alexander, Bradley Baetz, and Frederic Buclin discovered an SQL injection vulnerability in the Bug.create WebService function in Bugzilla, a web-based bug tracking system, which allows remote attackers to execute arbitrary SQL commands.

The oldstable distribution (etch) isn't affected by this problem.

For the stable distribution (lenny), this problem has been fixed in version 3.0.4.1-2+lenny2.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your bugzilla packages.");

  script_tag(name:"affected", value:"'bugzilla' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);