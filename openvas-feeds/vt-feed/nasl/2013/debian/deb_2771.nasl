# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702771");
  script_cve_id("CVE-2013-4256", "CVE-2013-4258");
  script_tag(name:"creation_date", value:"2013-10-08 22:00:00 +0000 (Tue, 08 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2771)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2771");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2771");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nas' package(s) announced via the DSA-2771 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hamid Zamani discovered multiple security problems (buffer overflows, format string vulnerabilities and missing input sanitising), which could lead to the execution of arbitrary code.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.9.2-4squeeze1.

For the stable distribution (wheezy), these problems have been fixed in version 1.9.3-5wheezy1.

For the testing distribution (jessie), these problems have been fixed in version 1.9.3-6.

For the unstable distribution (sid), these problems have been fixed in version 1.9.3-6.

We recommend that you upgrade your nas packages.");

  script_tag(name:"affected", value:"'nas' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);