# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69327");
  script_cve_id("CVE-2008-7265", "CVE-2010-3867", "CVE-2010-4652");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2191");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2191");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-2191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in ProFTPD, a versatile, virtual-hosting FTP daemon:

CVE-2008-7265

Incorrect handling of the ABOR command could lead to denial of service through elevated CPU consumption.

CVE-2010-3867

Several directory traversal vulnerabilities have been discovered in the mod_site_misc module.

CVE-2010-4652

A SQL injection vulnerability was discovered in the mod_sql module.

For the oldstable distribution (lenny), this problem has been fixed in version 1.3.1-17lenny6.

The stable distribution (squeeze) and the unstable distribution (sid) are not affected, these vulnerabilities have been fixed prior to the release of Debian 6.0 (squeeze).

We recommend that you upgrade your proftpd-dfsg packages.");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
