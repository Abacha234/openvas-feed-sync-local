# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703648");
  script_cve_id("CVE-2016-6504", "CVE-2016-6505", "CVE-2016-6506", "CVE-2016-6507", "CVE-2016-6508", "CVE-2016-6509", "CVE-2016-6510", "CVE-2016-6511");
  script_tag(name:"creation_date", value:"2016-08-11 22:00:00 +0000 (Thu, 11 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:33:00 +0000 (Mon, 28 Nov 2016)");

  script_name("Debian: Security Advisory (DSA-3648)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3648");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3648");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-3648 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the dissectors for NDS, PacketBB, WSP, MMSE, RLC, LDSS, RLC and OpenFlow, which could result in denial of service or the execution of arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u8.

For the testing distribution (stretch), these problems have been fixed in version 2.0.5+ga3be9c6-1.

For the unstable distribution (sid), these problems have been fixed in version 2.0.5+ga3be9c6-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);