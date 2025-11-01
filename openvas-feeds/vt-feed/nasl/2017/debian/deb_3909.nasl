# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703909");
  script_cve_id("CVE-2017-11103");
  script_tag(name:"creation_date", value:"2017-07-13 22:00:00 +0000 (Thu, 13 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3909)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3909");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3909");
  script_xref(name:"URL", value:"https://orpheus-lyre.info/");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2017-11103.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-3909 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeffrey Altman, Viktor Duchovni and Nico Williams identified a mutual authentication bypass vulnerability in samba, the SMB/CIFS file, print, and login server. Also known as Orpheus' Lyre, this vulnerability is located in Samba Kerberos Key Distribution Center (KDC-REP) component and could be used by an attacker on the network path to impersonate a server.

More details can be found on the vulnerability website ([link moved to references]) and on the Samba project website ( [link moved to references])

For the oldstable distribution (jessie), this problem has been fixed in version 2:4.2.14+dfsg-0+deb8u7.

For the stable distribution (stretch), this problem has been fixed in version 2:4.5.8+dfsg-2+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 2:4.6.5+dfsg-4.

For the unstable distribution (sid), this problem has been fixed in version 2:4.6.5+dfsg-4.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);