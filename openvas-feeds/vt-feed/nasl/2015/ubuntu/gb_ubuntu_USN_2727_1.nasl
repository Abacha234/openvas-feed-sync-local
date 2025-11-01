# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842448");
  script_cve_id("CVE-2015-3308", "CVE-2015-6251");
  script_tag(name:"creation_date", value:"2015-09-18 08:43:31 +0000 (Fri, 18 Sep 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2727-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2727-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28' package(s) announced via the USN-2727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GnuTLS incorrectly handled parsing CRL distribution
points. A remote attacker could possibly use this issue to cause a denial
of service, or execute arbitrary code. (CVE-2015-3308)

Kurt Roeckx discovered that GnuTLS incorrectly handled a long
DistinguishedName (DN) entry in a certificate. A remote attacker could
possibly use this issue to cause a denial of service, or execute arbitrary
code. (CVE-2015-6251)");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
