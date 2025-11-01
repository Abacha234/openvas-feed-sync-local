# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703719");
  script_cve_id("CVE-2016-9373", "CVE-2016-9374", "CVE-2016-9375", "CVE-2016-9376");
  script_tag(name:"creation_date", value:"2016-11-20 23:00:00 +0000 (Sun, 20 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3719)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3719");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3719");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-3719 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wireshark, a network protocol analyzer, contained several vulnerabilities in the dissectors for DCERPC, AllJoyn, DTN, and OpenFlow, that could lead to various crashes, denial-of-service, or execution of arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u10.

For the unstable distribution (sid), these problems have been fixed in version 2.2.2+g9c5aae3-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);