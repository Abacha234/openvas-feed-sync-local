# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703625");
  script_cve_id("CVE-2016-3948", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_tag(name:"creation_date", value:"2016-08-02 05:27:49 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3625)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3625");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3625");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DSA-3625 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in the Squid caching proxy.

CVE-2016-4051: CESG and Yuriy M. Kaminskiy discovered that Squid cachemgr.cgi was vulnerable to a buffer overflow when processing remotely supplied inputs relayed through Squid.

CVE-2016-4052: CESG discovered that a buffer overflow made Squid vulnerable to a Denial of Service (DoS) attack when processing ESI responses.

CVE-2016-4053: CESG found that Squid was vulnerable to public information disclosure of the server stack layout when processing ESI responses.

CVE-2016-4054: CESG discovered that Squid was vulnerable to remote code execution when processing ESI responses.

CVE-2016-4554: Jianjun Chen found that Squid was vulnerable to a header smuggling attack that could lead to cache poisoning and to bypass of same-origin security policy in Squid and some client browsers.

CVE-2016-4555, CVE-2016-4556: 'bfek-18' and '@vftable' found that Squid was vulnerable to a Denial of Service (DoS) attack when processing ESI responses, due to incorrect pointer handling and reference counting.

For the stable distribution (jessie), these problems have been fixed in version 3.4.8-6+deb8u3.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 3.5.19-1.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);