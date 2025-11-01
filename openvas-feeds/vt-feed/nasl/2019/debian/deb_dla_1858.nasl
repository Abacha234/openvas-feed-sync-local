# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891858");
  script_cve_id("CVE-2019-12525", "CVE-2019-12529");
  script_tag(name:"creation_date", value:"2019-07-21 02:00:14 +0000 (Sun, 21 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-26 20:18:00 +0000 (Tue, 26 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-1858)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1858");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1858");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DLA-1858 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squid, a high-performance proxy caching server for web clients, has been found vulnerable to denial of service attacks associated with HTTP authentication header processing.

CVE-2019-12525

Due to incorrect buffer management Squid is vulnerable to a denial of service attack when processing HTTP Digest Authentication credentials.

Due to incorrect input validation the HTTP Request header parser for Digest authentication may access memory outside the allocated memory buffer.

On systems with memory access protections this can result in the Squid process being terminated unexpectedly. Resulting in a denial of service for all clients using the proxy.

CVE-2019-12529

Due to incorrect buffer management Squid is vulnerable to a denial of service attack when processing HTTP Basic Authentication credentials.

Due to incorrect string termination the Basic authentication credentials decoder may access memory outside the decode buffer.

On systems with memory access protections this can result in the Squid process being terminated unexpectedly. Resulting in a denial of service for all clients using the proxy.

For Debian 8 Jessie, these problems have been fixed in version 3.4.8-6+deb8u8.

We recommend that you upgrade your squid3 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);