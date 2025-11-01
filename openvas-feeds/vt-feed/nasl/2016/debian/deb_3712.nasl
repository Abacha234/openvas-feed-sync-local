# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703712");
  script_cve_id("CVE-2015-8971");
  script_tag(name:"creation_date", value:"2016-11-12 23:00:00 +0000 (Sat, 12 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-24 19:44:00 +0000 (Mon, 24 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-3712)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3712");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3712");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'terminology' package(s) announced via the DSA-3712 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicolas Braud-Santoni discovered that incorrect sanitising of character escape sequences in the Terminology terminal emulator may result in the execution of arbitrary commands.

For the stable distribution (jessie), this problem has been fixed in version 0.7.0-1+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your terminology packages.");

  script_tag(name:"affected", value:"'terminology' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);