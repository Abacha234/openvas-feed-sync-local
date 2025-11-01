# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703387");
  script_cve_id("CVE-2015-7762", "CVE-2015-7763");
  script_tag(name:"creation_date", value:"2016-05-06 09:59:05 +0000 (Fri, 06 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3387");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3387");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-3387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"John Stumpo discovered that OpenAFS, a distributed file system, does not fully initialize certain network packets before transmitting them. This can lead to a disclosure of the plaintext of previously processed packets.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.6.1-3+deb7u5.

For the stable distribution (jessie), these problems have been fixed in version 1.6.9-2+deb8u4.

For the testing distribution (stretch) and the unstable distribution (sid), these problems have been fixed in version 1.6.15-1.

We recommend that you upgrade your openafs packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);