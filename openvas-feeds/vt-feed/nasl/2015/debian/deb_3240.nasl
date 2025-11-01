# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703240");
  script_cve_id("CVE-2015-3153");
  script_tag(name:"creation_date", value:"2015-04-28 22:00:00 +0000 (Tue, 28 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3240");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3240");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-3240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that cURL, an URL transfer library, if configured to use a proxy server with the HTTPS protocol, by default could send to the proxy the same HTTP headers it sends to the destination server, possibly leaking sensitive information.

For the stable distribution (jessie), this problem has been fixed in version 7.38.0-4+deb8u2.

For the testing distribution (stretch), this problem will be fixed in version 7.42.1-1.

For the unstable distribution (sid), this problem has been fixed in version 7.42.1-1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);