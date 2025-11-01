# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53652");
  script_cve_id("CVE-2003-0468", "CVE-2003-0540");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-363");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-363");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postfix' package(s) announced via the DSA-363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The postfix mail transport agent in Debian 3.0 contains two vulnerabilities:

CAN-2003-0468: Postfix would allow an attacker to bounce-scan private networks or use the daemon as a DDoS tool by forcing the daemon to connect to an arbitrary service at an arbitrary IP address and either receiving a bounce message or observing queue operations to infer the status of the delivery attempt.

CAN-2003-0540: a malformed envelope address can 1) cause the queue manager to lock up until an entry is removed from the queue and 2) lock up the smtp listener leading to a denial of service.

For the current stable distribution (woody) these problems have been fixed in version 1.1.11-0.woody3.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your postfix package.");

  script_tag(name:"affected", value:"'postfix' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);