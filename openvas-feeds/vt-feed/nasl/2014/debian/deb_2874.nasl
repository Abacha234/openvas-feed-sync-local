# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702874");
  script_cve_id("CVE-2014-0467");
  script_tag(name:"creation_date", value:"2014-03-11 23:00:00 +0000 (Tue, 11 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2874)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2874");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2874");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mutt' package(s) announced via the DSA-2874 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Beatrice Torracca and Evgeni Golov discovered a buffer overflow in the mutt mailreader. Malformed RFC2047 header lines could result in denial of service or potentially the execution of arbitrary code.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.5.20-9+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in version 1.5.21-6.2+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 1.5.22-2.

We recommend that you upgrade your mutt packages.");

  script_tag(name:"affected", value:"'mutt' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);