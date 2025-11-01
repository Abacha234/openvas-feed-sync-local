# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71471");
  script_cve_id("CVE-2012-2947", "CVE-2012-2948");
  script_tag(name:"creation_date", value:"2012-08-10 07:05:29 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2493)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2493");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2493");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-2493 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Asterisk, a PBX and telephony toolkit.

CVE-2012-2947

The IAX2 channel driver allows remote attackers to cause a denial of service (daemon crash) by placing a call on hold (when a certain mohinterpret setting is enabled).

CVE-2012-2948

The Skinny channel driver allows remote authenticated users to cause a denial of service (NULL pointer dereference and daemon crash) by closing a connection in off-hook mode.

In addition, it was discovered that Asterisk does not set the alwaysauthreject option by default in the SIP channel driver. This allows remote attackers to observe a difference in response behavior and check for the presence of account names. (CVE-2011-2666) System administrators concerned by this user enumerating vulnerability should enable the alwaysauthreject option in the configuration. We do not plan to change the default setting in the stable version (Asterisk 1.6) in order to preserve backwards compatibility.

For the stable distribution (squeeze), this problem has been fixed in version 1:1.6.2.9-2+squeeze6.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 1:1.8.13.0~dfsg-1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);