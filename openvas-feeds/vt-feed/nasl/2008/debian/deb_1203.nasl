# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57565");
  script_cve_id("CVE-2006-5170");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1203");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1203");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpam-ldap' package(s) announced via the DSA-1203 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Rigler discovered that the PAM module for authentication against LDAP servers processes PasswordPolicyReponse control messages incorrectly, which might lead to an attacker being able to login into a suspended system account.

For the stable distribution (sarge) this problem has been fixed in version 178-1sarge3. Due to technical problems with the security buildd infrastructure this update lacks a build for the Sun Sparc architecture. It will be released as soon as the problems are resolved.

For the unstable distribution (sid) this problem has been fixed in version 180-1.2.

We recommend that you upgrade your libpam-ldap package.");

  script_tag(name:"affected", value:"'libpam-ldap' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);