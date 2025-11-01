# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55539");
  script_cve_id("CVE-2005-2963");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-844)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-844");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-844");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mod-auth-shadow' package(s) announced via the DSA-844 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in mod_auth_shadow, an Apache module that lets users perform HTTP authentication against /etc/shadow, has been discovered. The module runs for all locations that use the 'require group' directive which would bypass access restrictions controlled by another authorisation mechanism, such as AuthGroupFile file, if the username is listed in the password file and in the gshadow file in the proper group and the supplied password matches against the one in the shadow file.

This update requires an explicit 'AuthShadow on' statement if website authentication should be checked against /etc/shadow.

For the old stable distribution (woody) this problem has been fixed in version 1.3-3.1woody.2.

For the stable distribution (sarge) this problem has been fixed in version 1.4-1sarge1.

For the unstable distribution (sid) this problem has been fixed in version 1.4-2.

We recommend that you upgrade your libapache-mod-auth-shadow package.");

  script_tag(name:"affected", value:"'mod-auth-shadow' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);