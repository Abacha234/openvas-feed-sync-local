# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704774");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-25211", "CVE-2020-25643", "CVE-2020-25645");
  script_tag(name:"creation_date", value:"2020-10-20 03:00:10 +0000 (Tue, 20 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-4774)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4774");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4774");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4774 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service or information leaks.

CVE-2020-12351

Andy Nguyen discovered a flaw in the Bluetooth implementation in the way L2CAP packets with A2MP CID are handled. A remote attacker in short distance knowing the victim's Bluetooth device address can send a malicious l2cap packet and cause a denial of service or possibly arbitrary code execution with kernel privileges.

CVE-2020-12352

Andy Nguyen discovered a flaw in the Bluetooth implementation. Stack memory is not properly initialised when handling certain AMP packets. A remote attacker in short distance knowing the victim's Bluetooth device address can retrieve kernel stack information.

CVE-2020-25211

A flaw was discovered in netfilter subsystem. A local attacker able to inject conntrack Netlink configuration can cause a denial of service.

CVE-2020-25643

ChenNan Of Chaitin Security Research Lab discovered a flaw in the hdlc_ppp module. Improper input validation in the ppp_cp_parse_cr() function may lead to memory corruption and information disclosure.

CVE-2020-25645

A flaw was discovered in the interface driver for GENEVE encapsulated traffic when combined with IPsec. If IPsec is configured to encrypt traffic for the specific UDP port used by the GENEVE tunnel, tunneled data isn't correctly routed over the encrypted link and sent unencrypted instead.

For the stable distribution (buster), these problems have been fixed in version 4.19.152-1. The vulnerabilities are fixed by rebasing to the new stable upstream version 4.19.152 which includes additional bugfixes.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);