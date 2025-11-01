# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67983");
  script_cve_id("CVE-2010-2944");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2096");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2096");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zope-ldapuserfolder' package(s) announced via the DSA-2096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeremy James discovered that in LDAPUserFolder, a Zope extension used to authenticate against an LDAP server, the authentication code does not verify the password provided for the emergency user. Malicious users that manage to get the emergency user login can use this flaw to gain administrative access to the Zope instance, by providing an arbitrary password.

For the stable distribution (lenny), this problem has been fixed in version 2.9-1+lenny1.

The package no longer exists in the upcoming stable distribution (squeeze) or the unstable distribution.

We recommend that you upgrade your zope-ldapuserfolder package.");

  script_tag(name:"affected", value:"'zope-ldapuserfolder' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);