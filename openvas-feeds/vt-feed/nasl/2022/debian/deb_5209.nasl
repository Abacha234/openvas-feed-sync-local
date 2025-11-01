# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705209");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2022-08-18 01:00:11 +0000 (Thu, 18 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5209)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5209");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5209");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/net-snmp");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'net-snmp' package(s) announced via the DSA-5209 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yu Zhang and Nanyu Zhong discovered several vulnerabilities in net-snmp, a suite of Simple Network Management Protocol applications, which could result in denial of service or the execution of arbitrary code.

For the stable distribution (bullseye), these problems have been fixed in version 5.9+dfsg-4+deb11u1.

We recommend that you upgrade your net-snmp packages.

For the detailed security status of net-snmp please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);