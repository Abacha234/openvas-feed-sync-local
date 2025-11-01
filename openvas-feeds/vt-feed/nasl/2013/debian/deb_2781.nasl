# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702781");
  script_cve_id("CVE-2013-1445");
  script_tag(name:"creation_date", value:"2013-10-17 22:00:00 +0000 (Thu, 17 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2781)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2781");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2781");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-crypto' package(s) announced via the DSA-2781 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A cryptographic vulnerability was discovered in the pseudo random number generator in python-crypto.

In some situations, a race condition could prevent the reseeding of the generator when multiple processes are forked from the same parent. This would lead it to generate identical output on all processes, which might leak sensitive values like cryptographic keys.

For the oldstable distribution (squeeze), this problem has been fixed in version 2.1.0-2+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 2.6-4+deb7u3.

For the testing distribution (jessie), this problem has been fixed in version 2.6.1-2.

For the unstable distribution (sid), this problem has been fixed in version 2.6.1-1.

We recommend that you upgrade your python-crypto packages.");

  script_tag(name:"affected", value:"'python-crypto' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);