# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702760");
  script_cve_id("CVE-2012-4502", "CVE-2012-4503");
  script_tag(name:"creation_date", value:"2013-09-17 22:00:00 +0000 (Tue, 17 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2760)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2760");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2760");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chrony' package(s) announced via the DSA-2760 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered two security problems in the Chrony time synchronisation software (buffer overflows and use of uninitialised data in command replies).

For the oldstable distribution (squeeze), these problems will be fixed soon in 1.24-3+squeeze1 (due to a technical restriction in the archive processing scripts the two updates cannot be released together).

For the stable distribution (wheezy), these problems have been fixed in version 1.24-3.1+deb7u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your chrony packages.");

  script_tag(name:"affected", value:"'chrony' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);