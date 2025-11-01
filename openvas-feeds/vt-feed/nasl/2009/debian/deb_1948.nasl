# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66515");
  script_cve_id("CVE-2009-3563");
  script_tag(name:"creation_date", value:"2009-12-14 22:06:43 +0000 (Mon, 14 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1948)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1948");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1948");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DSA-1948 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Robin Park and Dmitri Vinokurov discovered that the daemon component of the ntp package, a reference implementation of the NTP protocol, is not properly reacting to certain incoming packets.

An unexpected NTP mode 7 packet (MODE_PRIVATE) with spoofed IP data can lead ntpd to reply with a mode 7 response to the spoofed address. This may result in the service playing packet ping-pong with other ntp servers or even itself which causes CPU usage and excessive disk use due to logging. An attacker can use this to conduct denial of service attacks.

For the oldstable distribution (etch), this problem has been fixed in version 1:4.2.2.p4+dfsg-2etch4.

For the stable distribution (lenny), this problem has been fixed in version 1:4.2.4p4+dfsg-8lenny3.

For the testing (squeeze) and unstable (sid) distribution, this problem will be fixed soon.

We recommend that you upgrade your ntp packages.");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);