# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703277");
  script_cve_id("CVE-2015-3808", "CVE-2015-3809", "CVE-2015-3810", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-3814", "CVE-2015-3815", "CVE-2015-3906");
  script_tag(name:"creation_date", value:"2015-06-01 22:00:00 +0000 (Mon, 01 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3277");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3277");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-3277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the dissectors/parsers for LBMR, web sockets, WCP, X11, IEEE 802.11 and Android Logcat, which could result in denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.8.2-5wheezy16.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1.12.5+g5819e5b-1.

For the unstable distribution (sid), these problems have been fixed in version 1.12.5+g5819e5b-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);