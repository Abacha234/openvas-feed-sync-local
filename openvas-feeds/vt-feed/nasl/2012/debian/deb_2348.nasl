# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70564");
  script_cve_id("CVE-2010-4170", "CVE-2010-4171", "CVE-2011-2503");
  script_tag(name:"creation_date", value:"2012-02-11 07:31:24 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2348");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2348");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'systemtap' package(s) announced via the DSA-2348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in SystemTap, an instrumentation system for Linux:

CVE-2011-2503

It was discovered that a race condition in staprun could lead to privilege escalation.

CVE-2010-4170

It was discovered that insufficient validation of environment variables in staprun could lead to privilege escalation.

CVE-2010-4171

It was discovered that insufficient validation of module unloading could lead to denial of service.

For the stable distribution (squeeze), this problem has been fixed in version 1.2-5+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 1.6-1.

We recommend that you upgrade your systemtap packages.");

  script_tag(name:"affected", value:"'systemtap' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);