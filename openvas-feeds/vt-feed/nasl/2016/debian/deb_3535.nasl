# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703535");
  script_cve_id("CVE-2016-2385");
  script_tag(name:"creation_date", value:"2016-03-28 22:00:00 +0000 (Mon, 28 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3535");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3535");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kamailio' package(s) announced via the DSA-3535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stelios Tsampas discovered a buffer overflow in the Kamailio SIP proxy which might result in the execution of arbitrary code.

For the stable distribution (jessie), this problem has been fixed in version 4.2.0-2+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 4.3.4-2.

For the unstable distribution (sid), this problem has been fixed in version 4.3.4-2.

We recommend that you upgrade your kamailio packages.");

  script_tag(name:"affected", value:"'kamailio' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);