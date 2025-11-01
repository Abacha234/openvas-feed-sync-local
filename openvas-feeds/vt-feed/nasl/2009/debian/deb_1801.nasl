# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64032");
  script_cve_id("CVE-2009-0159", "CVE-2009-1252");
  script_tag(name:"creation_date", value:"2009-05-25 18:59:33 +0000 (Mon, 25 May 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1801)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1801");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1801");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DSA-1801 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in NTP, the Network Time Protocol reference implementation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0159

A buffer overflow in ntpq allow a remote NTP server to create a denial of service attack or to execute arbitrary code via a crafted response.

CVE-2009-1252

A buffer overflow in ntpd allows a remote attacker to create a denial of service attack or to execute arbitrary code when the autokey functionality is enabled.

For the old stable distribution (etch), these problems have been fixed in version 4.2.2.p4+dfsg-2etch3.

For the stable distribution (lenny), these problems have been fixed in version 4.2.4p4+dfsg-8lenny2.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your ntp package.");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);