# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704314");
  script_cve_id("CVE-2018-18065");
  script_tag(name:"creation_date", value:"2018-10-10 22:00:00 +0000 (Wed, 10 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-16 18:15:00 +0000 (Wed, 16 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4314");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4314");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/net-snmp");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'net-snmp' package(s) announced via the DSA-4314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Magnus Klaaborg Stubman discovered a NULL pointer dereference bug in net-snmp, a suite of Simple Network Management Protocol applications, allowing a remote, authenticated attacker to crash the snmpd process (causing a denial of service).

For the stable distribution (stretch), this problem has been fixed in version 5.7.3+dfsg-1.7+deb9u1.

We recommend that you upgrade your net-snmp packages.

For the detailed security status of net-snmp please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);