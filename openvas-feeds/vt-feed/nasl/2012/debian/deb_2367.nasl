# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70579");
  script_cve_id("CVE-2011-4597", "CVE-2011-4598");
  script_tag(name:"creation_date", value:"2012-02-11 07:35:09 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2367)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2367");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2367");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-2367 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Asterisk, an Open Source PBX and telephony toolkit:

CVE-2011-4597

Ben Williams discovered that it was possible to enumerate SIP user names in some configurations. Please see the upstream advisory for details.

This update only modifies the sample sip.conf configuration file. Please see README.Debian for more information on how to update your installation.

CVE-2011-4598

Kristijan Vrban discovered that Asterisk can be crashed with malformed SIP packets if the automon feature is enabled.

For the oldstable distribution (lenny), this problem has been fixed in version 1:1.4.21.2~dfsg-3+lenny6.

For the stable distribution (squeeze), this problem has been fixed in version 1:1.6.2.9-2+squeeze4.

For the unstable distribution (sid), this problem has been fixed in version 1:1.8.8.0~dfsg-1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);