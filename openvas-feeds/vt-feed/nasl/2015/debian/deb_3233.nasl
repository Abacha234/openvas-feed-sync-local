# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703233");
  script_cve_id("CVE-2015-1863");
  script_tag(name:"creation_date", value:"2015-04-23 22:00:00 +0000 (Thu, 23 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3233");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3233");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DSA-3233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Google security team and the smart hardware research group of Alibaba security team discovered a flaw in how wpa_supplicant used SSID information when creating or updating P2P peer entries. A remote attacker can use this flaw to cause wpa_supplicant to crash, expose memory contents, and potentially execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 1.0-3+deb7u2. Note that this issue does not affect the binary packages distributed in Debian as the CONFIG_P2P is not enabled for the build.

For the upcoming stable distribution (jessie), this problem has been fixed in version 2.3-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.3-2.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);