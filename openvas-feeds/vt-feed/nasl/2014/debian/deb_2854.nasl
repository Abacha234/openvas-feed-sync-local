# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702854");
  script_cve_id("CVE-2014-0044", "CVE-2014-0045");
  script_tag(name:"creation_date", value:"2014-02-04 23:00:00 +0000 (Tue, 04 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2854)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2854");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2854");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mumble' package(s) announced via the DSA-2854 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in mumble, a low latency VoIP client. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2014-0044

It was discovered that a malformed Opus voice packet sent to a Mumble client could trigger a NULL pointer dereference or an out-of-bounds array access. A malicious remote attacker could exploit this flaw to mount a denial of service attack against a mumble client by causing the application to crash.

CVE-2014-0045

It was discovered that a malformed Opus voice packet sent to a Mumble client could trigger a heap-based buffer overflow. A malicious remote attacker could use this flaw to cause a client crash (denial of service) or potentially use it to execute arbitrary code.

The oldstable distribution (squeeze) is not affected by these problems.

For the stable distribution (wheezy), these problems have been fixed in version 1.2.3-349-g315b5f5-2.2+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your mumble packages.");

  script_tag(name:"affected", value:"'mumble' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);