# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891645");
  script_cve_id("CVE-2019-5716", "CVE-2019-5717", "CVE-2019-5719");
  script_tag(name:"creation_date", value:"2019-01-28 23:00:00 +0000 (Mon, 28 Jan 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-1645)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1645");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1645");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DLA-1645 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues in wireshark, a network traffic analyzer, have been found. Dissectors of:

ISAKMP, a Internet Security Association and Key Management Protocol

P_MUL, a reliable multicast transfer protocol

6LoWPAN, IPv6 over Low power Wireless Personal Area Network

are affected.

CVE-2019-5719

Mateusz Jurczyk found that a missing encryption block in a packet could crash the ISAKMP dissector.

CVE-2019-5717

It was found that the P_MUL dissector could crash when a malformed packet contains an illegal Data PDU sequence number of 0. Such a packet may not be analysed.

CVE-2019-5716

It was found that the 6LoWPAN dissector could crash when a malformed packet does not contain IPHC information though the header says it should.

For Debian 8 Jessie, these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u17.

We recommend that you upgrade your wireshark packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);