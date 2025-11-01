# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60435");
  script_cve_id("CVE-2007-6418");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1501");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dspam' package(s) announced via the DSA-1501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tobias Grutzmacher discovered that a Debian-provided CRON script in dspam, a statistical spam filter, included a database password on the command line. This allowed a local attacker to read the contents of the dspam database, such as emails.

The old stable distribution (sarge) does not contain the dspam package.

For the stable distribution (etch), this problem has been fixed in version 3.6.8-5etch1.

For the unstable distribution (sid), this problem has been fixed in version 3.6.8-5.1.

We recommend that you upgrade your dspam package.");

  script_tag(name:"affected", value:"'dspam' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);