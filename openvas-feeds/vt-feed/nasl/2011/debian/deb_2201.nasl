# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69337");
  script_cve_id("CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2201)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2201");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2201");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-2201 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Huzaifa Sidhpurwala, Joernchen, and Xiaopeng Zhang discovered several vulnerabilities in the Wireshark network traffic analyzer. Vulnerabilities in the DCT3, LDAP and SMB dissectors and in the code to parse pcag-ng files could lead to denial of service or the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in version 1.0.2-3+lenny13.

For the stable distribution (squeeze), this problem has been fixed in version 1.2.11-6+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 1.4.4-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);