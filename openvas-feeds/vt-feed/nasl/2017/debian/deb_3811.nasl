# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703811");
  script_cve_id("CVE-2017-5596", "CVE-2017-5597", "CVE-2017-6014", "CVE-2017-6467", "CVE-2017-6468", "CVE-2017-6469", "CVE-2017-6470", "CVE-2017-6471", "CVE-2017-6472", "CVE-2017-6473", "CVE-2017-6474");
  script_tag(name:"creation_date", value:"2017-03-17 23:00:00 +0000 (Fri, 17 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3811)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3811");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3811");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-3811 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wireshark, a network protocol analyzer, contained several vulnerabilities in the dissectors for ASTERIX, DHCPv6, NetScaler, LDSS, IAX2, WSP, K12 and STANAG 4607, that could lead to various crashes, denial-of-service or execution of arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u11.

For the unstable distribution (sid), these problems have been fixed in version 2.2.5+g440fd4d-2.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);