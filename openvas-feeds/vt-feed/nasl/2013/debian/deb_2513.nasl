# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702513");
  script_cve_id("CVE-2012-1948", "CVE-2012-1954", "CVE-2012-1967");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2513");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2513");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-2513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Iceape internet suite, an unbranded version of Seamonkey:

CVE-2012-1948

Benoit Jacob, Jesse Ruderman, Christian Holler, and Bill McCloskey identified several memory safety problems that may lead to the execution of arbitrary code.

CVE-2012-1954

Abhishek Arya discovered a use-after-free problem in nsDocument::AdoptNode that may lead to the execution of arbitrary code.

CVE-2012-1967

moz_bug_r_a4 discovered that in certain cases, javascript: URLs can be executed so that scripts can escape the JavaScript sandbox and run with elevated privileges. This can lead to arbitrary code execution.

For the stable distribution (squeeze), this problem has been fixed in version 2.0.11-14.

For the unstable (sid) and testing (wheezy) distribution, this problem will be fixed soon.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);