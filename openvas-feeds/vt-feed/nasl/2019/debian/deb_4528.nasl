# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704528");
  script_tag(name:"creation_date", value:"2019-09-21 02:00:06 +0000 (Sat, 21 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-4528)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4528");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4528");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bird");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bird' package(s) announced via the DSA-4528 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel McCarney discovered that the BIRD internet routing daemon incorrectly validated RFC 8203 messages in it's BGP daemon, resulting in a stack buffer overflow.

For the stable distribution (buster), this problem has been fixed in version 1.6.6-1+deb10u1. In addition this update fixes an incomplete revocation of privileges and a crash triggerable via the CLI (the latter two bugs are also fixed in the oldstable distribution (stretch) which is not affected by CVE-2019-16159).

We recommend that you upgrade your bird packages.

For the detailed security status of bird please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bird' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);