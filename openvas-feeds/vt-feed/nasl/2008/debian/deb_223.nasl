# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53303");
  script_cve_id("CVE-2002-1390");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-223");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-223");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'geneweb' package(s) announced via the DSA-223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security issue has been discovered by Daniel de Rauglaudre, upstream author of geneweb, a genealogical software with web interface. It runs as a daemon on port 2317 by default. Paths are not properly sanitized, so a carefully crafted URL lead geneweb to read and display arbitrary files of the system it runs on.

For the current stable distribution (woody) this problem has been fixed in version 4.06-2.

The old stable distribution (potato) is not affected.

For the unstable distribution (sid) this problem has been fixed in version 4.09-1.

We recommend that you upgrade your geneweb package.");

  script_tag(name:"affected", value:"'geneweb' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);