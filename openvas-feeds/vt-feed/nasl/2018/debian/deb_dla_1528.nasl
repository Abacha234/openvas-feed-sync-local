# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891528");
  script_cve_id("CVE-2018-17540");
  script_tag(name:"creation_date", value:"2018-10-01 22:00:00 +0000 (Mon, 01 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-01 01:15:00 +0000 (Sun, 01 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-1528)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1528");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1528");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DLA-1528 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a denial-of-service vulnerability in strongswan, a virtual private network (VPN) client and server.

Verification of an RSA signature with a very short public key caused an integer underflow in a length check that resulted in a heap buffer overflow.

For Debian 8 Jessie, this issue has been fixed in strongswan version 5.2.1-6+deb8u8.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);