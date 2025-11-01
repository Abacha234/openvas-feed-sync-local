# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703745");
  script_cve_id("CVE-2016-10002");
  script_tag(name:"creation_date", value:"2016-12-23 23:00:00 +0000 (Fri, 23 Dec 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3745)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3745");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3745");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DSA-3745 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Saulius Lapinskas from Lithuanian State Social Insurance Fund Board discovered that Squid3, a fully featured web proxy cache, does not properly process responses to If-None-Modified HTTP conditional requests, leading to client-specific Cookie data being leaked to other clients. A remote attacker can take advantage of this flaw to discover private and sensitive information about another clients browsing session.

For the stable distribution (jessie), this problem has been fixed in version 3.4.8-6+deb8u4. In addition, this update includes a fix for #819563.

For the unstable distribution (sid), this problem has been fixed in version 3.5.23-1.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);