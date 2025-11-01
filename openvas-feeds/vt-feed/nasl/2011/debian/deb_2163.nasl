# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69110");
  script_cve_id("CVE-2011-0696", "CVE-2011-0697");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2163");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2163");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-2163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Django web development framework:

CVE-2011-0696

For several reasons the internal CSRF protection was not used to validate AJAX requests in the past. However, it was discovered that this exception can be exploited with a combination of browser plugins and redirects and thus is not sufficient.

CVE-2011-0697

It was discovered that the file upload form is prone to cross-site scripting attacks via the file name.

It is important to note that this update introduces minor backward incompatibilities due to the fixes for the above issues. For the exact details, please see: and in particular the Backwards incompatible changes section.

Packages in the oldstable distribution (lenny) are not affected by these problems.

For the stable distribution (squeeze), this problem has been fixed in version 1.2.3-3+squeeze1.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.2.5-1.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);