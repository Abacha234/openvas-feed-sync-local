# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704994");
  script_cve_id("CVE-2021-25219");
  script_tag(name:"creation_date", value:"2021-10-30 01:00:09 +0000 (Sat, 30 Oct 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 04:15:00 +0000 (Thu, 04 Nov 2021)");

  script_name("Debian: Security Advisory (DSA-4994)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4994");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4994");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-4994 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kishore Kumar Kothapalli discovered that the lame server cache in BIND, a DNS server implementation, can be abused by an attacker to significantly degrade resolver performance, resulting in denial of service (large delays for responses for client queries and DNS timeouts on client hosts).

For the oldstable distribution (buster), this problem has been fixed in version 1:9.11.5.P4+dfsg-5.1+deb10u6.

For the stable distribution (bullseye), this problem has been fixed in version 1:9.16.22-1~deb11u1.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);