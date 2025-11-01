# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70698");
  script_cve_id("CVE-2011-1528", "CVE-2011-1529");
  script_tag(name:"creation_date", value:"2012-02-11 08:26:12 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2379");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2379");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-2379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Key Distribution Center (KDC) in Kerberos 5 crashes when processing certain crafted requests:

CVE-2011-1528

When the LDAP backend is used, remote users can trigger a KDC daemon crash and denial of service.

CVE-2011-1529

When the LDAP or Berkeley DB backend is used, remote users can trigger a NULL pointer dereference in the KDC daemon and a denial of service.

The oldstable distribution (lenny) is not affected by these problems.

For the stable distribution (squeeze), these problems have been fixed in version 1.8.3+dfsg-4squeeze5.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 1.10+dfsg~alpha1-1.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);