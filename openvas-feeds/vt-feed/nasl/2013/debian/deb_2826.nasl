# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702826");
  script_cve_id("CVE-2013-6890");
  script_tag(name:"creation_date", value:"2013-12-21 23:00:00 +0000 (Sat, 21 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2826)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2826");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2826");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'denyhosts' package(s) announced via the DSA-2826 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Helmut Grohne discovered that denyhosts, a tool preventing SSH brute-force attacks, could be used to perform remote denial of service against the SSH daemon. Incorrectly specified regular expressions used to detect brute force attacks in authentication logs could be exploited by a malicious user to forge crafted login names in order to make denyhosts ban arbitrary IP addresses.

For the oldstable distribution (squeeze), this problem has been fixed in version 2.6-7+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in version 2.6-10+deb7u2.

For the testing distribution (jessie), this problem has been fixed in version 2.6-10.1.

For the unstable distribution (sid), this problem has been fixed in version 2.6-10.1.

We recommend that you upgrade your denyhosts packages.");

  script_tag(name:"affected", value:"'denyhosts' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);