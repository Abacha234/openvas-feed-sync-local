# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53557");
  script_cve_id("CVE-2005-1151", "CVE-2005-1152");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-728)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-728");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-728");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qpopper' package(s) announced via the DSA-728 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This advisory does only cover updated packages for Debian 3.0 alias woody. For reference below is the original advisory text:

Two bugs have been discovered in qpopper, an enhanced Post Office Protocol (POP3) server. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-1151

Jens Steube discovered that while processing local files owned or provided by a normal user privileges weren't dropped, which could lead to the overwriting or creation of arbitrary files as root.

CAN-2005-1152

The upstream developers noticed that qpopper could be tricked to creating group- or world-writable files.

For the stable distribution (woody) these problems have been fixed in version 4.0.4-2.woody.5.

For the testing distribution (sarge) these problems have been fixed in version 4.0.5-4sarge1.

For the unstable distribution (sid) these problems will be fixed in version 4.0.5-4sarge1.

We recommend that you upgrade your qpopper package.");

  script_tag(name:"affected", value:"'qpopper' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);