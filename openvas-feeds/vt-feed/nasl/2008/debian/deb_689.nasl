# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53519");
  script_cve_id("CVE-2005-0088");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-689");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-689");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapache-mod-python' package(s) announced via the DSA-689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Graham Dumpleton discovered a flaw which can affect anyone using the publisher handle of the Apache Software Foundation's mod_python. The publisher handle lets you publish objects inside modules to make them callable via URL. The flaw allows a carefully crafted URL to obtain extra information that should not be visible (information leak).

For the stable distribution (woody) this problem has been fixed in version 2.7.8-0.0woody5.

For the unstable distribution (sid) this problem has been fixed in version 2.7.10-4 of libapache-mod-python and in version 3.1.3-3 of libapache2-mod-python.

We recommend that you upgrade your libapache-mod-python package.");

  script_tag(name:"affected", value:"'libapache-mod-python' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);