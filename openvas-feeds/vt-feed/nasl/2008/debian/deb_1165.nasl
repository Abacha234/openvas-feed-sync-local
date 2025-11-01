# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57333");
  script_cve_id("CVE-2006-3126");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1165");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1165");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'capi4hylafax' package(s) announced via the DSA-1165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lionel Elie Mamane discovered a security vulnerability in capi4hylafax, tools for faxing over a CAPI 2.0 device, that allows remote attackers to execute arbitrary commands on the fax receiving system.

For the stable distribution (sarge) this problem has been fixed in version 01.02.03-10sarge2.

For the unstable distribution (sid) this problem has been fixed in version 01.03.00.99.svn.300-3.

We recommend that you upgrade your capi4hylafax package.");

  script_tag(name:"affected", value:"'capi4hylafax' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);