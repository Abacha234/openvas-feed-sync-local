# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61642");
  script_cve_id("CVE-2007-5712", "CVE-2008-3909");
  script_tag(name:"creation_date", value:"2008-09-24 15:42:31 +0000 (Wed, 24 Sep 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1640)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1640");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1640");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-1640 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon Willison discovered that in Django, a Python web framework, the feature to retain HTTP POST data during user reauthentication allowed a remote attacker to perform unauthorized modification of data through cross site request forgery. This is possible regardless of the Django plugin to prevent cross site request forgery being enabled. The Common Vulnerabilities and Exposures project identifies this issue as CVE-2008-3909.

In this update the affected feature is disabled, this is in accordance with upstream's preferred solution for this situation.

This update takes the opportunity to also include a relatively minor denial of service attack in the internationalisation framework, known as CVE-2007-5712.

For the stable distribution (etch), these problems have been fixed in version 0.95.1-1etch2.

For the unstable distribution (sid), these problems have been fixed in version 1.0-1.

We recommend that you upgrade your python-django package.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);