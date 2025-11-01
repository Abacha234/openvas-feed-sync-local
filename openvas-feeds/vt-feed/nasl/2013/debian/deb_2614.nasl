# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702614");
  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960", "CVE-2012-5961", "CVE-2012-5962", "CVE-2012-5963", "CVE-2012-5964", "CVE-2012-5965");
  script_tag(name:"creation_date", value:"2013-01-31 23:00:00 +0000 (Thu, 31 Jan 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2614)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2614");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2614");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libupnp' package(s) announced via the DSA-2614 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple stack-based buffer overflows were discovered in libupnp, a library used for handling the Universal Plug and Play protocol. HD Moore from Rapid7 discovered that SSDP queries where not correctly handled by the unique_service_name() function.

An attacker sending carefully crafted SSDP queries to a daemon built on libupnp could generate a buffer overflow, overwriting the stack, leading to the daemon crash and possible remote code execution.

For the stable distribution (squeeze), these problems have been fixed in version 1:1.6.6-5+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in version 1:1.6.17-1.2.

For the unstable distribution (sid), these problems have been fixed in version 1:1.6.17-1.2.

We recommend that you upgrade your libupnp packages.");

  script_tag(name:"affected", value:"'libupnp' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);