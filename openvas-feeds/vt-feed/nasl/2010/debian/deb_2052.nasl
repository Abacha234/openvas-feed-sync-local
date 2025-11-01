# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67405");
  script_cve_id("CVE-2010-1321");
  script_tag(name:"creation_date", value:"2010-06-03 20:55:24 +0000 (Thu, 03 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2052");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2052");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-2052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Shawn Emery discovered that in MIT Kerberos 5 (krb5), a system for authenticating users and services on a network, a null pointer dereference flaw in the Generic Security Service Application Program Interface (GSS-API) library could allow an authenticated remote attacker to crash any server application using the GSS-API authentication mechanism, by sending a specially-crafted GSS-API token with a missing checksum field.

For the stable distribution (lenny), this problem has been fixed in version 1.6.dfsg.4~beta1-5lenny4.

For the testing distribution (squeeze), this problem has been fixed in version 1.8.1+dfsg-3.

For the unstable distribution (sid), this problem has been fixed in version 1.8.1+dfsg-3.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);