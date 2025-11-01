# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703143");
  script_cve_id("CVE-2015-0377", "CVE-2015-0418");
  script_tag(name:"creation_date", value:"2015-01-27 23:00:00 +0000 (Tue, 27 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3143)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3143");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3143");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virtualbox' package(s) announced via the DSA-3143 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in VirtualBox, a x86 virtualisation solution, which might result in denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 4.1.18-dfsg-2+deb7u4.

For the unstable distribution (sid), these problems have been fixed in version 4.3.18-dfsg-2.

We recommend that you upgrade your virtualbox packages.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);