# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703904");
  script_cve_id("CVE-2017-3142", "CVE-2017-3143");
  script_tag(name:"creation_date", value:"2017-07-07 22:00:00 +0000 (Fri, 07 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3904)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3904");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3904");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-3904 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Clement Berthaux from Synaktiv discovered two vulnerabilities in BIND, a DNS server implementation. They allow an attacker to bypass TSIG authentication by sending crafted DNS packets to a server.

CVE-2017-3142

An attacker who is able to send and receive messages to an authoritative DNS server and who has knowledge of a valid TSIG key name may be able to circumvent TSIG authentication of AXFR requests via a carefully constructed request packet. A server that relies solely on TSIG keys for protection with no other ACL protection could be manipulated into:

providing an AXFR of a zone to an unauthorized recipient

accepting bogus NOTIFY packets

CVE-2017-3143

An attacker who is able to send and receive messages to an authoritative DNS server and who has knowledge of a valid TSIG key name for the zone and service being targeted may be able to manipulate BIND into accepting an unauthorized dynamic update.

For the oldstable distribution (jessie), these problems have been fixed in version 1:9.9.5.dfsg-9+deb8u12.

For the stable distribution (stretch), these problems have been fixed in version 1:9.10.3.dfsg.P4-12.3+deb9u1.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);